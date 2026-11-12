"""TLS configuration: protocol version, certificate expiry, legacy protocols."""
from __future__ import annotations

import socket
import ssl
import time
import warnings

from ..models import Finding, Severity, Status

CAT = "TLS"


def certificate_invalid(message: str) -> Finding:
    return Finding("tls.certificate", CAT, "Valid TLS certificate", Status.FAIL, Severity.CRITICAL,
                   "The certificate failed verification, so browsers show a full-page security warning and "
                   "the connection cannot be trusted.",
                   "Install a certificate from a trusted CA (e.g. Let's Encrypt) that matches the hostname and is not expired.",
                   evidence=message)


def _name(entries) -> str:
    flat = {k: v for rdn in entries or () for k, v in rdn}
    return flat.get("organizationName") or flat.get("commonName") or "unknown"


def expiry_finding(days_left: int, issuer: str, not_after: str) -> Finding:
    title = "Certificate expiry"
    evidence = f"Issuer: {issuer}; expires {not_after}"
    if days_left < 0:
        return Finding("tls.expiry", CAT, title, Status.FAIL, Severity.CRITICAL,
                       "The certificate has expired.", "Renew the certificate now.", evidence=evidence)
    if days_left < 14:
        return Finding("tls.expiry", CAT, title, Status.FAIL, Severity.HIGH,
                       f"The certificate expires in {days_left} days.",
                       "Renew now and automate renewal (e.g. certbot).", evidence=evidence)
    if days_left < 30:
        return Finding("tls.expiry", CAT, title, Status.WARN, Severity.MEDIUM,
                       f"The certificate expires in {days_left} days.",
                       "Make sure automatic renewal is working.", evidence=evidence)
    return Finding("tls.expiry", CAT, title, Status.PASS, Severity.HIGH,
                   f"Certificate is valid for another {days_left} days.", evidence=evidence)


def protocol_finding(version: str | None, cipher: str | None) -> Finding:
    title = "Negotiated TLS version"
    evidence = f"{version}, cipher {cipher}"
    if version == "TLSv1.3":
        return Finding("tls.version", CAT, title, Status.PASS, Severity.MEDIUM,
                       "Uses TLS 1.3, the current and most secure version.", evidence=evidence)
    if version == "TLSv1.2":
        return Finding("tls.version", CAT, title, Status.PASS, Severity.MEDIUM,
                       "Uses TLS 1.2 (secure). Enabling TLS 1.3 would be faster and stronger.", evidence=evidence)
    return Finding("tls.version", CAT, title, Status.FAIL, Severity.HIGH,
                   f"Best available protocol is {version}, which is deprecated and insecure.",
                   "Enable TLS 1.2 and 1.3 on the server.", evidence=evidence)


def legacy_protocol_supported(
    host: str, port: int, version: ssl.TLSVersion, timeout: float, connect_ip: str | None = None
) -> bool | None:
    """True = server accepted it, False = refused, None = could not test locally."""
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = version
            ctx.maximum_version = version
            try:
                ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
            except ssl.SSLError:
                pass
    except (ValueError, ssl.SSLError):
        return None
    try:
        with socket.create_connection((connect_ip or host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host):
                return True
    except ssl.SSLError as exc:
        msg = str(exc).lower()
        local_refusal = "no protocols available" in msg or "no_protocols_available" in msg
        if local_refusal or ("unsupported protocol" in msg and "alert" not in msg):
            return None  # our local OpenSSL build refuses to even try
        return False
    except OSError:
        return False


def legacy_finding(results: dict[str, bool | None]) -> Finding:
    accepted = [name for name, ok in results.items() if ok]
    unknown = [name for name, ok in results.items() if ok is None]
    title = "Legacy TLS 1.0 / 1.1 disabled"
    if accepted:
        return Finding("tls.legacy", CAT, title, Status.FAIL, Severity.MEDIUM,
                       f"The server still accepts {', '.join(accepted)}, which are deprecated (RFC 8996) and vulnerable "
                       "to downgrade attacks.",
                       "Disable TLS 1.0 and 1.1; allow only TLS 1.2+.", evidence=", ".join(accepted))
    if unknown and len(unknown) == len(results):
        return Finding("tls.legacy", CAT, title, Status.INFO, Severity.INFO,
                       "Could not test legacy protocols: the local OpenSSL build does not support them.")
    return Finding("tls.legacy", CAT, title, Status.PASS, Severity.MEDIUM,
                   "TLS 1.0 and 1.1 are refused.")


def run(host: str, port: int, timeout: float = 10.0, connect_ip: str | None = None) -> list[Finding]:
    """connect_ip pins the TCP connection to an address vetted by the SSRF guard."""
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((connect_ip or host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                version, cipher, cert = tls.version(), (tls.cipher() or (None,))[0], tls.getpeercert()
    except ssl.SSLCertVerificationError:
        return []  # already reported by the scanner as an invalid certificate
    except OSError as exc:
        return [Finding("tls.handshake", CAT, "TLS handshake", Status.INFO, Severity.INFO,
                        f"Could not analyse TLS details: {exc}")]

    findings = [protocol_finding(version, cipher)]
    if cert and cert.get("notAfter"):
        not_after = str(cert["notAfter"])
        days_left = int((ssl.cert_time_to_seconds(not_after) - time.time()) // 86400)
        findings.append(expiry_finding(days_left, _name(cert.get("issuer")), not_after))

    results = {
        "TLS 1.0": legacy_protocol_supported(host, port, ssl.TLSVersion.TLSv1, timeout, connect_ip),
        "TLS 1.1": legacy_protocol_supported(host, port, ssl.TLSVersion.TLSv1_1, timeout, connect_ip),
    }
    findings.append(legacy_finding(results))
    return findings
