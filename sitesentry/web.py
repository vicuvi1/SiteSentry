"""Local web UI: python -m sitesentry --serve"""
from __future__ import annotations

import json
import secrets
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from . import report
from .scanner import ScanError, scan


class Handler(BaseHTTPRequestHandler):
    server_version = "SiteSentry"

    def log_message(self, fmt, *args):  # keep the terminal tidy
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
        self.end_headers()
        self.wfile.write(data)

    def _json(self, status: int, payload: dict) -> None:
        self._send(status, json.dumps(payload), "application/json; charset=utf-8")

    def do_GET(self) -> None:  # noqa: N802
        url = urlsplit(self.path)
        if url.path in ("/", "/index.html"):
            self._send(200, report.ui_page(), "text/html; charset=utf-8")
        elif url.path == "/api/scan":
            qs = parse_qs(url.query)
            target = (qs.get("url") or [""])[0]
            ports = (qs.get("ports") or ["0"])[0] == "1"
            print(f"  scanning {target}{' (+ports)' if ports else ''} ...", flush=True)
            try:
                result = scan(target, check_ports=ports, timeout=self.server.scan_timeout)  # type: ignore[attr-defined]
            except ValueError as exc:
                self._json(400, {"error": str(exc)})
            except ScanError as exc:
                self._json(502, {"error": str(exc)})
            except Exception as exc:  # never crash the server on one bad scan
                self._json(500, {"error": f"Unexpected error: {exc}"})
            else:
                print(f"  done: {result.final_url} -> {result.grade} ({result.score}/100)", flush=True)
                self._json(200, result.to_dict())
        elif url.path == "/favicon.ico":
            self.send_response(204)
            self.end_headers()
        else:
            self._json(404, {"error": "Not found"})


def serve(host: str = "127.0.0.1", port: int = 8765, open_browser: bool = True, timeout: float = 10.0) -> None:
    httpd = ThreadingHTTPServer((host, port), Handler)
    httpd.scan_timeout = timeout  # type: ignore[attr-defined]
    shown = "127.0.0.1" if host in ("0.0.0.0", "::") else host
    address = f"http://{shown}:{httpd.server_address[1]}/"
    print(f"\n  SiteSentry, made by Victor Barbuta\n  Running at {address}\n  Press Ctrl+C to stop.\n", flush=True)
    if open_browser:
        threading.Timer(0.6, lambda: webbrowser.open(address)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n  Stopped.")
    finally:
        httpd.server_close()
