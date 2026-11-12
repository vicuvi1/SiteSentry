"""CORS misconfiguration: does the server trust an arbitrary Origin?"""
from __future__ import annotations

from ..models import Finding, Severity, Status
from ..net import HttpResponse

CAT = "CORS"
PROBE_ORIGIN = "https://sitesentry-cors-probe.example"
REF = "https://portswigger.net/web-security/cors"


def check(resp: HttpResponse) -> Finding:
    acao = resp.header("access-control-allow-origin")
    creds = (resp.header("access-control-allow-credentials") or "").strip().lower() == "true"
    title = "Cross-origin resource sharing (CORS)"
    evidence = f"Access-Control-Allow-Origin: {acao}" + ("; Allow-Credentials: true" if creds else "") if acao else ""

    if acao is None:
        return Finding("cors.origin", CAT, title, Status.PASS, Severity.HIGH,
                       "An untrusted Origin received no CORS permission.", reference=REF)
    if acao.strip() == PROBE_ORIGIN:
        if creds:
            return Finding("cors.origin", CAT, title, Status.FAIL, Severity.HIGH,
                           "The server reflects ANY Origin and allows credentials. A malicious website could read "
                           "logged-in users' data from this site.",
                           "Only allow a fixed list of trusted origins; never reflect the Origin header blindly.",
                           evidence=evidence, reference=REF)
        return Finding("cors.origin", CAT, title, Status.WARN, Severity.LOW,
                       "The server reflects any Origin (without credentials).",
                       "Use an allow-list of origins instead of reflecting the request header.",
                       evidence=evidence, reference=REF)
    if acao.strip() == "null" and creds:
        return Finding("cors.origin", CAT, title, Status.FAIL, Severity.MEDIUM,
                       "The 'null' origin is trusted with credentials; sandboxed iframes can abuse this.",
                       "Never allow the 'null' origin.", evidence=evidence, reference=REF)
    if acao.strip() == "*":
        return Finding("cors.origin", CAT, title, Status.INFO, Severity.INFO,
                       "Any origin may read responses (without cookies). Fine for public content and APIs.",
                       evidence=evidence, reference=REF)
    return Finding("cors.origin", CAT, title, Status.PASS, Severity.HIGH,
                   "CORS is limited to specific origins.", evidence=evidence, reference=REF)
