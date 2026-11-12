"""HTTPS availability and HTTP -> HTTPS redirection."""
from __future__ import annotations

from ..models import Finding, Severity, Status
from ..net import HttpResponse

CAT = "Transport"


def https_available(ok: bool, error: str = "") -> Finding:
    if ok:
        return Finding("transport.https", CAT, "HTTPS available", Status.PASS, Severity.CRITICAL,
                       "The site is reachable over encrypted HTTPS.")
    return Finding("transport.https", CAT, "HTTPS available", Status.FAIL, Severity.CRITICAL,
                   "The site could not be reached over HTTPS, so everything (including passwords) travels in plain text.",
                   "Enable HTTPS with a free certificate from Let's Encrypt.", evidence=error)


def http_redirect(resp: HttpResponse | None, error: str = "") -> Finding:
    title = "HTTP redirects to HTTPS"
    if resp is None:
        return Finding("transport.redirect", CAT, title, Status.PASS, Severity.MEDIUM,
                       "Plain HTTP is not served at all, so there is no unencrypted version of the site.",
                       evidence=error)
    target = resp.redirect_target if resp.is_redirect else None
    if target and target.lower().startswith("https://"):
        permanent = resp.status in (301, 308)
        return Finding("transport.redirect", CAT, title, Status.PASS, Severity.MEDIUM,
                       f"http:// sends a {resp.status} redirect to HTTPS"
                       + ("." if permanent else " (a permanent 301/308 would be slightly better)."),
                       evidence=f"{resp.status} Location: {target}")
    return Finding("transport.redirect", CAT, title, Status.FAIL, Severity.MEDIUM,
                   f"Requesting http:// returned {resp.status} without redirecting to HTTPS, so visitors can stay on "
                   "an unencrypted connection.",
                   "Redirect all HTTP traffic to HTTPS with a 301 response.",
                   evidence=f"{resp.status} {resp.reason}" + (f" -> {target}" if target else ""))
