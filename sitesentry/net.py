"""Minimal HTTP client built on the standard library.

We deliberately avoid urllib's automatic redirect handling so the scanner can
inspect every hop (e.g. to see whether http:// redirects to https://) and read
all repeated headers such as multiple Set-Cookie lines.
"""
from __future__ import annotations

import http.client
import ssl
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

from . import __version__

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


def request(
    url: str,
    *,
    timeout: float = 10.0,
    verify: bool = True,
    method: str = "GET",
    extra_headers: dict[str, str] | None = None,
) -> HttpResponse:
    """Send one request without following redirects.

    ssl.SSLCertVerificationError is re-raised untouched so callers can report
    an invalid certificate; every other network problem becomes FetchError.
    """
    parts = urlsplit(url)
    if not parts.hostname:
        raise FetchError(f"Invalid URL: {url}")
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query

    if parts.scheme == "https":
        ctx = ssl.create_default_context() if verify else ssl._create_unverified_context()  # noqa: SLF001
        conn: http.client.HTTPConnection = http.client.HTTPSConnection(
            parts.hostname, parts.port, timeout=timeout, context=ctx
        )
    elif parts.scheme == "http":
        conn = http.client.HTTPConnection(parts.hostname, parts.port, timeout=timeout)
    else:
        raise FetchError(f"Unsupported scheme: {parts.scheme}")

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
    url: str, *, timeout: float = 10.0, verify: bool = True, max_redirects: int = 5
) -> list[HttpResponse]:
    """Follow redirects manually and return every response in order."""
    chain: list[HttpResponse] = []
    current = url
    for _ in range(max_redirects + 1):
        resp = request(current, timeout=timeout, verify=verify)
        chain.append(resp)
        if not resp.is_redirect:
            break
        current = resp.redirect_target  # type: ignore[assignment]
    return chain
