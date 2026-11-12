"""Orchestrates all checks against one target."""
from __future__ import annotations

import ssl
import time
from collections.abc import Callable
from datetime import UTC, datetime
from urllib.parse import urlsplit, urlunsplit

from . import scoring
from .checks import content, cookies, cors, disclosure, email_dns, headers, misc, tls, transport
from .models import Finding, ScanResult
from .net import CA_BUNDLE, FetchError, HttpResponse, fetch_chain, is_chain_error, request
from .safety import BlockedTarget, TargetGuard


class ScanError(Exception):
    """The target could not be reached at all."""


def normalize_target(target: str) -> str:
    value = target.strip()
    if not value:
        raise ValueError("Please enter a website address.")
    if "://" not in value:
        value = "https://" + value
    parts = urlsplit(value)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError(f"'{target}' is not a valid http(s) URL.")
    if any(c.isspace() for c in parts.netloc) or parts.username or parts.password:
        raise ValueError(f"'{target}' is not a valid http(s) URL.")
    return urlunsplit((parts.scheme, parts.netloc, parts.path or "/", parts.query, ""))


def _netloc(host: str, port: int, default: int) -> str:
    name = f"[{host}]" if ":" in host else host  # IPv6 literals need brackets
    return name if port == default else f"{name}:{port}"


def scan(
    target: str,
    *,
    timeout: float = 10.0,
    check_ports: bool = False,
    check_dns: bool = True,
    guard: TargetGuard | None = None,
    log: Callable[[str], None] | None = None,
) -> ScanResult:
    """Scan one website.

    Pass a TargetGuard when scanning on behalf of other people (the web
    server does): internal addresses then raise BlockedTarget, including
    ones reached through redirects.
    """
    log = log or (lambda _msg: None)
    started = time.time()
    url = normalize_target(target)
    parts = urlsplit(url)
    host = parts.hostname or ""
    # A port typed together with a scheme belongs to that scheme only; the other scheme uses its
    # default (https://host:8443 -> plain HTTP is checked on :80, not on the TLS port). Without a
    # scheme ("host:8080") we can't tell, so the port is used for both attempts.
    explicit_scheme = "://" in target
    https_port = parts.port if parts.port and (parts.scheme == "https" or not explicit_scheme) else 443
    http_port = parts.port if parts.port and (parts.scheme == "http" or not explicit_scheme) else 80
    https_url = urlunsplit(("https", _netloc(host, https_port, 443), parts.path, parts.query, ""))
    http_url = urlunsplit(("http", _netloc(host, http_port, 80), parts.path, parts.query, ""))

    pinned_ip: str | None = None
    if guard:
        try:
            pinned_ip = guard.resolve(host, https_port)  # raises BlockedTarget
        except OSError as exc:
            raise ScanError(f"Could not resolve {host}: {exc}") from exc

    findings: list[Finding] = []
    notes: list[str] = []
    chain: list[HttpResponse] | None = None
    https_ok = False
    cert_ok = False
    chain_only = False

    log(f"Connecting to {https_url}")
    try:
        chain = fetch_chain(https_url, timeout=timeout, guard=guard, notes=notes)
        https_ok = cert_ok = True
    except ssl.SSLCertVerificationError as exc:
        https_ok = True
        message = getattr(exc, "verify_message", "") or str(exc)
        chain_only = is_chain_error(exc)
        findings.append(tls.chain_incomplete(message, bool(CA_BUNDLE)) if chain_only else tls.certificate_invalid(message))
        try:
            chain = fetch_chain(https_url, timeout=timeout, verify=False, guard=guard, notes=notes)
        except (FetchError, ssl.SSLError) as exc2:
            notes.append(f"HTTPS content unreadable: {exc2}")
    except FetchError as exc:
        notes.append(f"HTTPS unavailable: {exc}")
    findings.append(transport.https_available(https_ok, "" if https_ok else (notes[-1] if notes else "")))

    if chain is None:
        log(f"Falling back to {http_url}")
        try:
            chain = fetch_chain(http_url, timeout=timeout, guard=guard, notes=notes)
        except (FetchError, ssl.SSLError) as exc:
            raise ScanError(f"Could not reach {host}: {exc}") from exc

    final = chain[-1]
    if len(chain) > 1:
        notes.append("Redirect chain: " + " -> ".join(f"{r.status} {r.url}" for r in chain))
    log(f"Analysing response from {final.url} ({final.status})")

    findings += headers.run(final)
    findings += disclosure.run(chain)
    findings += cookies.run(chain)
    findings += content.run(final)

    log("Testing CORS policy")
    try:
        probe = request(final.url, timeout=timeout, verify=cert_ok, guard=guard,
                        extra_headers={"Origin": cors.PROBE_ORIGIN})
        findings.append(cors.check(probe))
    except (FetchError, ssl.SSLError) as exc:
        notes.append(f"CORS probe failed: {exc}")

    log("Checking HTTP to HTTPS redirect")
    try:
        findings.append(transport.http_redirect(request(http_url, timeout=timeout, guard=guard)))
    except (FetchError, ssl.SSLError) as exc:
        findings.append(transport.http_redirect(None, str(exc)))

    if https_ok and (cert_ok or chain_only):
        log("Inspecting TLS configuration")
        findings += tls.run(host, https_port, timeout, connect_ip=pinned_ip, verify=cert_ok)

    log("Looking for security.txt")
    origin = urlunsplit((urlsplit(final.url).scheme, urlsplit(final.url).netloc, "", "", ""))
    try:  # RFC 9116 allows redirecting to the canonical location
        findings.append(misc.security_txt(
            fetch_chain(origin + "/.well-known/security.txt", timeout=timeout, verify=cert_ok, guard=guard)[-1]))
    except (FetchError, ssl.SSLError):
        findings.append(misc.security_txt(None))

    if check_dns:
        log("Checking SPF, DMARC and CAA records")
        findings += email_dns.run(host, timeout=min(timeout, 4.0))

    if check_ports:
        log("Probing commonly abused service ports")
        findings += misc.scan_ports(pinned_ip or host)

    log("Calculating grade")
    result = ScanResult(
        target=target,
        final_url=final.url,
        started_at=datetime.fromtimestamp(started, UTC).strftime("%Y-%m-%d %H:%M UTC"),
        duration_seconds=time.time() - started,
        findings=findings,
        notes=notes,
    )
    result.score, result.grade = scoring.score(findings)
    return result


__all__ = ["BlockedTarget", "ScanError", "TargetGuard", "normalize_target", "scan"]
