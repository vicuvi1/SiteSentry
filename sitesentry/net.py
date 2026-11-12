"""Minimal HTTP client built on the standard library.

We deliberately avoid urllib's automatic redirect handling so the scanner can
inspect every hop (e.g. to see whether http:// redirects to https://) and read
all repeated headers such as multiple Set-Cookie lines.
"""
from __future__ import annotations

import http.client
import socket
import ssl
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

from . import __version__
from .safety import TargetGuard

USER_AGENT = f"SiteSentry/{__version__} (passive website security scanner)"
MAX_BODY_BYTES = 512 * 1024
REDIRECT_CODES = {301, 302, 303, 307, 308}


class FetchError(Exception):
    """Raised when a request cannot be completed (DNS, refused, timeout...)."""


@dataclass
class HttpResponse:
    url: str
    status: int
    reason: str
    headers: list[tuple[str, str]] = field(default_factory=list)
    body: bytes = b""

    def header(self, name: str) -> str | None:
        name = name.lower()
        for key, value in self.headers:
            if key.lower() == name:
                return value
        return None

    def header_all(self, name: str) -> list[str]:
        name = name.lower()
        return [value for key, value in self.headers if key.lower() == name]

    @property
    def is_https(self) -> bool:
        return self.url.lower().startswith("https://")

    @property
    def is_redirect(self) -> bool:
        return self.status in REDIRECT_CODES and bool(self.header("location"))

    @property
    def redirect_target(self) -> str | None:
        loc = self.header("location")
        return urljoin(self.url, loc) if loc else None

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")


try:  # optional: Mozilla's CA bundle, so results don't depend on this machine's trust store
    import certifi
    CA_BUNDLE: str | None = certifi.where()
except ImportError:
    CA_BUNDLE = None

# OpenSSL codes meaning "couldn't build a chain to a trusted root" (missing intermediate or unknown root),
# as opposed to a certificate that is actually invalid (expired, wrong hostname, self-signed...).
CHAIN_ERROR_CODES = {2, 20, 21}


def make_ssl_context(verify: bool = True) -> ssl.SSLContext:
    """TLS client context: system roots + Mozilla roots (if certifi is installed), TLS 1.2+.

    Windows only trusts roots already cached on the machine (browsers fetch missing ones on demand),
    so without certifi valid sites can look untrusted. With verify=False we deliberately still read a
    site whose certificate is broken (already reported as a finding) so the remaining checks can run.
    """
    if not verify:
        ctx = ssl._create_unverified_context()  # noqa: S323
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        return ctx
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    if CA_BUNDLE:
        ctx.load_verify_locations(CA_BUNDLE)
    return ctx


def is_chain_error(exc: ssl.SSLCertVerificationError) -> bool:
    return getattr(exc, "verify_code", None) in CHAIN_ERROR_CODES


class _PinnedHTTPConnection(http.client.HTTPConnection):
    """Connects to a pre-vetted IP while keeping the real Host header."""

    def __init__(self, host: str, port: int | None, *, ip: str, timeout: float):
        super().__init__(host, port, timeout=timeout)
        self._ip = ip

    def connect(self) -> None:
        self.sock = socket.create_connection((self._ip, self.port), self.timeout)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """Connects to a pre-vetted IP; TLS SNI and certificate checks still use the hostname."""

    def __init__(self, host: str, port: int | None, *, ip: str, timeout: float, context: ssl.SSLContext):
        super().__init__(host, port, timeout=timeout, context=context)
        self._ip = ip
        self._ctx = context

    def connect(self) -> None:
        sock = socket.create_connection((self._ip, self.port), self.timeout)
        self.sock = self._ctx.wrap_socket(sock, server_hostname=self.host)


def request(
    url: str,
    *,
    timeout: float = 10.0,
    verify: bool = True,
    method: str = "GET",
    extra_headers: dict[str, str] | None = None,
    guard: TargetGuard | None = None,
) -> HttpResponse:
    """Send one request without following redirects.

    ssl.SSLCertVerificationError is re-raised untouched so callers can report
    an invalid certificate; every other network problem becomes FetchError.
    With a guard, internal targets raise BlockedTarget and the connection is
    pinned to the vetted IP address.
    """
    parts = urlsplit(url)
    if not parts.hostname:
        raise FetchError(f"Invalid URL: {url}")
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    if parts.scheme not in ("http", "https"):
        raise FetchError(f"Unsupported scheme: {parts.scheme}")

    try:
        default_port = 443 if parts.scheme == "https" else 80
        ip = guard.resolve(parts.hostname, parts.port or default_port) if guard else None
    except OSError as exc:
        raise FetchError(f"{type(exc).__name__}: {exc}") from exc

    conn: http.client.HTTPConnection
    if parts.scheme == "https":
        ctx = make_ssl_context(verify)
        if ip:
            conn = _PinnedHTTPSConnection(parts.hostname, parts.port, ip=ip, timeout=timeout, context=ctx)
        else:
            conn = http.client.HTTPSConnection(parts.hostname, parts.port, timeout=timeout, context=ctx)
    elif ip:
        conn = _PinnedHTTPConnection(parts.hostname, parts.port, ip=ip, timeout=timeout)
    else:
        conn = http.client.HTTPConnection(parts.hostname, parts.port, timeout=timeout)

    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
        "Accept-Encoding": "identity",
        "Connection": "close",
    }
    if extra_headers:
        headers.update(extra_headers)

    try:
        conn.request(method, path, headers=headers)
        resp = conn.getresponse()
        body = resp.read(MAX_BODY_BYTES) if method != "HEAD" else b""
        return HttpResponse(url, resp.status, resp.reason, list(resp.getheaders()), body)
    except ssl.SSLCertVerificationError:
        raise
    except (OSError, http.client.HTTPException) as exc:
        raise FetchError(f"{type(exc).__name__}: {exc}") from exc
    finally:
        conn.close()


def fetch_chain(
    url: str,
    *,
    timeout: float = 10.0,
    verify: bool = True,
    max_redirects: int = 5,
    guard: TargetGuard | None = None,
) -> list[HttpResponse]:
    """Follow redirects manually and return every response in order.

    The guard (if any) is applied to every hop, so a redirect can't lead
    the scanner into an internal network.
    """
    chain: list[HttpResponse] = []
    current = url
    for _ in range(max_redirects + 1):
        resp = request(current, timeout=timeout, verify=verify, guard=guard)
        chain.append(resp)
        if not resp.is_redirect:
            break
        current = resp.redirect_target  # type: ignore[assignment]
    return chain
