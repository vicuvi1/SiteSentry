"""Local web UI: python -m sitesentry --serve

Security model (the server fetches URLs on behalf of whoever can reach it):
- SSRF guard: internal / private targets are refused, including via redirects,
  unless started with --allow-private (useful for scanning your own dev servers).
- Host header allow-list when bound to loopback, which blocks DNS-rebinding
  attacks where a malicious website tries to talk to the local UI.
- Per-client rate limit and a cap on concurrent scans.
- The port check is disabled whenever the server is reachable from other machines.
- Strict, nonce-based Content-Security-Policy and other security headers.
"""
from __future__ import annotations

import ipaddress
import json
import secrets
import threading
import time
import webbrowser
from collections import defaultdict, deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from . import report
from .safety import BlockedTarget, TargetGuard
from .scanner import ScanError, scan

RATE_LIMIT = 10          # scans ...
RATE_WINDOW = 60.0       # ... per client per this many seconds
MAX_CONCURRENT = 4       # scans running at the same time
LOOPBACK_NAMES = {"localhost", "127.0.0.1", "[::1]", "::1"}


def is_loopback(host: str) -> bool:
    if host in LOOPBACK_NAMES:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class RateLimiter:
    def __init__(self, limit: int = RATE_LIMIT, window: float = RATE_WINDOW):
        self.limit, self.window = limit, window
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, client: str) -> bool:
        now = time.monotonic()
        with self._lock:
            hits = self._hits[client]
            while hits and now - hits[0] > self.window:
                hits.popleft()
            if len(hits) >= self.limit:
                return False
            hits.append(now)
            return True


class SiteSentryServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, *, timeout: float = 10.0, allow_private: bool = False,
                 rate_limit: int = RATE_LIMIT):
        super().__init__(address, Handler)
        self.scan_timeout = timeout
        self.guard = TargetGuard(allow_private=allow_private)
        self.local_only = is_loopback(address[0])
        self.limiter = RateLimiter(limit=rate_limit)
        self.slots = threading.BoundedSemaphore(MAX_CONCURRENT)


class Handler(BaseHTTPRequestHandler):
    server: SiteSentryServer
    server_version = "SiteSentry"
    sys_version = ""  # don't advertise the Python version (we flag that in others!)

    def log_message(self, format, *args):  # keep the terminal tidy  # noqa: A002
        pass

    def _send(self, status: int, body: str, ctype: str) -> None:
        # Practise what we preach: the UI ships with a strict, nonce-based CSP.
        nonce = secrets.token_urlsafe(16)
        if ctype.startswith("text/html"):
            body = body.replace("<script>", f'<script nonce="{nonce}">')
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy",
                         f"default-src 'self'; script-src 'nonce-{nonce}'; style-src 'unsafe-inline'; "
                         "img-src 'self' data:; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; "
                         "form-action 'self'")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.end_headers()
        self.wfile.write(data)

    def _json(self, status: int, payload: dict) -> None:
        self._send(status, json.dumps(payload), "application/json; charset=utf-8")

    def _host_allowed(self) -> bool:
        """Reject foreign Host headers on a loopback-only server (DNS rebinding defence)."""
        if not self.server.local_only:
            return True
        host = (self.headers.get("Host") or "").strip().lower()
        if host.startswith("["):
            name = host.split("]")[0] + "]"
        else:
            name = host.rsplit(":", 1)[0] if ":" in host else host
        return name in LOOPBACK_NAMES

    def do_GET(self) -> None:  # noqa: N802
        if not self._host_allowed():
            self._json(421, {"error": "Unexpected Host header."})
            return
        url = urlsplit(self.path)
        if url.path in ("/", "/index.html"):
            self._send(200, report.ui_page(), "text/html; charset=utf-8")
        elif url.path == "/api/scan":
            self._scan(parse_qs(url.query))
        elif url.path == "/api/scan/stream":
            self._scan_stream(parse_qs(url.query))
        elif url.path == "/favicon.ico":
            self.send_response(204)
            self.end_headers()
        else:
            self._json(404, {"error": "Not found"})

    # -- shared admission control ------------------------------------------------

    def _admit(self, qs: dict[str, list[str]]) -> tuple[str, bool] | tuple[int, str]:
        """Return (target, ports) if the scan may run, else (http_status, error). Takes a scan slot."""
        target = (qs.get("url") or [""])[0][:2048]
        ports = (qs.get("ports") or ["0"])[0] == "1"
        if ports and not self.server.local_only:
            return 403, "The port check is disabled on shared servers. Run SiteSentry locally to use it."
        if not self.server.limiter.allow(self.client_address[0]):
            return 429, f"Too many scans. The limit is {self.server.limiter.limit} per minute."
        if not self.server.slots.acquire(blocking=False):
            return 503, "The server is busy with other scans. Try again in a few seconds."
        return target, ports

    def _run(self, target: str, ports: bool, log=None):
        """Run a scan; returns (status, payload)."""
        try:
            print(f"  scanning {target}{' (+ports)' if ports else ''} ...", flush=True)
            result = scan(target, check_ports=ports, timeout=self.server.scan_timeout, guard=self.server.guard, log=log)
        except ValueError as exc:
            return 400, {"error": str(exc)}
        except BlockedTarget as exc:
            return 403, {"error": str(exc)}
        except ScanError as exc:
            return 502, {"error": str(exc)}
        except (BrokenPipeError, ConnectionResetError):
            raise  # client went away mid-stream
        except Exception:  # never crash or leak internals on one bad scan
            return 500, {"error": "Unexpected error while scanning."}
        finally:
            self.server.slots.release()
        print(f"  done: {result.final_url} -> {result.grade} ({result.score}/100)", flush=True)
        return 200, result.to_dict()

    # -- endpoints -----------------------------------------------------------------

    def _scan(self, qs: dict[str, list[str]]) -> None:
        admitted = self._admit(qs)
        if isinstance(admitted[0], int):
            self._json(admitted[0], {"error": admitted[1]})
            return
        target, ports = admitted
        status, payload = self._run(str(target), bool(ports))
        self._json(status, payload)

    def _scan_stream(self, qs: dict[str, list[str]]) -> None:
        """Server-Sent Events: 'step' events while scanning, then one 'result' or 'fail' event."""
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True

        def emit(event: str, data: dict) -> None:
            self.wfile.write(f"event: {event}\ndata: {json.dumps(data)}\n\n".encode())
            self.wfile.flush()

        try:
            admitted = self._admit(qs)
            if isinstance(admitted[0], int):
                emit("fail", {"status": admitted[0], "error": admitted[1]})
                return
            target, ports = admitted
            started = time.monotonic()
            status, payload = self._run(str(target), bool(ports),
                                        log=lambda msg: emit("step", {"msg": msg, "t": round(time.monotonic() - started, 2)}))
            if status == 200:
                emit("result", payload)
            else:
                emit("fail", {"status": status, **payload})
        except (BrokenPipeError, ConnectionResetError):
            pass  # browser closed the tab; the scan was aborted by the failed write


def serve(host: str = "127.0.0.1", port: int = 8765, open_browser: bool = True, timeout: float = 10.0,
          allow_private: bool = False) -> None:
    httpd = SiteSentryServer((host, port), timeout=timeout, allow_private=allow_private)
    shown = "127.0.0.1" if host in ("0.0.0.0", "::") else host  # noqa: S104 - display only, not a bind
    address = f"http://{shown}:{httpd.server_address[1]}/"
    print(f"\n  SiteSentry, made by Victor Barbuta\n  Running at {address}", flush=True)
    if allow_private:
        print("  WARNING: --allow-private is on, so internal addresses can be scanned.", flush=True)
    if not httpd.local_only:
        print("  Shared mode: SSRF guard and rate limits on, port check disabled.", flush=True)
    print("  Press Ctrl+C to stop.\n", flush=True)
    if open_browser:
        threading.Timer(0.6, lambda: webbrowser.open(address)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n  Stopped.")
    finally:
        httpd.server_close()
