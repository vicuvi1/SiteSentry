"""HTTP security response headers (OWASP Secure Headers Project)."""
from __future__ import annotations

import re

from ..models import Finding, Severity, Status
from ..net import HttpResponse

CAT = "Security headers"
OWASP_HEADERS = "https://owasp.org/www-project-secure-headers/"
HSTS_MIN_SECONDS = 15_552_000  # 180 days


def parse_csp(policy: str) -> dict[str, list[str]]:
    directives: dict[str, list[str]] = {}
    for chunk in policy.split(";"):
        tokens = chunk.strip().split()
        if not tokens:
            continue
        name = tokens[0].lower()
        if name not in directives:  # first occurrence wins, per the spec
            directives[name] = [t.lower() for t in tokens[1:]]
    return directives


def check_hsts(value: str | None) -> Finding:
    base = dict(
        check_id="headers.hsts",
        category=CAT,
        title="Strict-Transport-Security (HSTS)",
        reference="https://developer.mozilla.org/docs/Web/HTTP/Headers/Strict-Transport-Security",
    )
    rec = "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains"
    if not value:
        return Finding(
            **base,
            status=Status.FAIL,
            severity=Severity.MEDIUM,
            detail="Browsers are not told to always use HTTPS, so a first visit or a typed "
            "http:// link can be downgraded by an attacker on the network (SSL stripping).",
            recommendation=rec,
        )
    match = re.search(r"max-age\s*=\s*\"?(\d+)", value, re.I)
    max_age = int(match.group(1)) if match else 0
    if max_age < HSTS_MIN_SECONDS:
        return Finding(
            **base,
            status=Status.WARN,
            severity=Severity.LOW,
            detail=f"HSTS is set but max-age is only {max_age} seconds (recommended at least 180 days).",
            recommendation=rec,
            evidence=value,
        )
    extra = " includeSubDomains is set." if "includesubdomains" in value.lower() else ""
    return Finding(
        **base,
        status=Status.PASS,
        severity=Severity.MEDIUM,
        detail=f"HSTS enforced for {max_age // 86400} days.{extra}",
        evidence=value,
    )


def csp_weaknesses(policy: str) -> list[str]:
    d = parse_csp(policy)
    script_src = d.get("script-src", d.get("default-src"))
    issues: list[str] = []
    if script_src is None:
        issues.append("no script-src or default-src, so scripts are not restricted")
        return issues
    has_nonce_or_hash = any(v.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) for v in script_src)
    if "'unsafe-inline'" in script_src and not has_nonce_or_hash:
        issues.append("'unsafe-inline' allows injected inline scripts (defeats XSS protection)")
    if "'unsafe-eval'" in script_src:
        issues.append("'unsafe-eval' allows eval() of strings")
    wild = [v for v in script_src if v in ("*", "http:", "https:", "data:")]
    if wild:
        issues.append(f"overly broad script sources: {' '.join(wild)}")
    return issues


def check_csp(policy: str | None, report_only: str | None) -> Finding:
    base = dict(
        check_id="headers.csp",
        category=CAT,
        title="Content-Security-Policy (CSP)",
        reference="https://developer.mozilla.org/docs/Web/HTTP/CSP",
    )
    rec = (
        "Define a CSP that only allows scripts from your own origin, e.g. "
        "Content-Security-Policy: default-src 'self'; object-src 'none'; frame-ancestors 'self'"
    )
    if not policy:
        detail = "No CSP header, so the browser has no second line of defence against cross-site scripting (XSS)."
        if report_only:
            detail = "Only Content-Security-Policy-Report-Only is set: violations are reported but nothing is blocked."
        return Finding(**base, status=Status.FAIL, severity=Severity.MEDIUM, detail=detail,
                       recommendation=rec, evidence=report_only or "")
    issues = csp_weaknesses(policy)
    if issues:
        return Finding(
            **base,
            status=Status.WARN,
            severity=Severity.LOW,
            detail="CSP is present but weak: " + "; ".join(issues) + ".",
            recommendation="Replace 'unsafe-inline'/'unsafe-eval' with nonces or hashes and list explicit script origins.",
            evidence=policy[:300],
        )
    return Finding(**base, status=Status.PASS, severity=Severity.MEDIUM,
                   detail="CSP restricts where scripts can load from.", evidence=policy[:300])


def check_clickjacking(xfo: str | None, csp: str | None) -> Finding:
    base = dict(
        check_id="headers.clickjacking",
        category=CAT,
        title="Clickjacking protection",
        reference="https://owasp.org/www-community/attacks/Clickjacking",
    )
    if csp and "frame-ancestors" in parse_csp(csp):
        return Finding(**base, status=Status.PASS, severity=Severity.MEDIUM,
                       detail="CSP frame-ancestors controls who can embed the page.",
                       evidence="frame-ancestors " + " ".join(parse_csp(csp)["frame-ancestors"]))
    value = (xfo or "").strip().upper()
    if value in ("DENY", "SAMEORIGIN"):
        return Finding(**base, status=Status.PASS, severity=Severity.MEDIUM,
                       detail=f"X-Frame-Options: {value} prevents other sites from framing the page.", evidence=xfo or "")
    if value.startswith("ALLOW-FROM"):
        return Finding(**base, status=Status.WARN, severity=Severity.LOW,
                       detail="X-Frame-Options ALLOW-FROM is ignored by modern browsers.",
                       recommendation="Use CSP frame-ancestors instead.", evidence=xfo or "")
    return Finding(
        **base,
        status=Status.FAIL,
        severity=Severity.MEDIUM,
        detail="Any website can load this page in an invisible iframe and trick users into clicking on it.",
        recommendation="Add X-Frame-Options: DENY (or SAMEORIGIN), or CSP frame-ancestors 'self'.",
    )


def check_nosniff(value: str | None) -> Finding:
    base = dict(check_id="headers.nosniff", category=CAT, title="X-Content-Type-Options",
                reference="https://developer.mozilla.org/docs/Web/HTTP/Headers/X-Content-Type-Options")
    if (value or "").strip().lower() == "nosniff":
        return Finding(**base, status=Status.PASS, severity=Severity.LOW,
                       detail="MIME-type sniffing is disabled.", evidence=value or "")
    return Finding(**base, status=Status.FAIL, severity=Severity.LOW,
                   detail="Browsers may 'sniff' and execute files with the wrong content type (e.g. an uploaded file run as script).",
                   recommendation="Add: X-Content-Type-Options: nosniff")


def check_referrer_policy(value: str | None) -> Finding:
    base = dict(check_id="headers.referrer", category=CAT, title="Referrer-Policy",
                reference="https://developer.mozilla.org/docs/Web/HTTP/Headers/Referrer-Policy")
    rec = "Add: Referrer-Policy: strict-origin-when-cross-origin"
    if not value:
        return Finding(**base, status=Status.FAIL, severity=Severity.LOW,
                       detail="No Referrer-Policy; full URLs (which may contain tokens or IDs) can leak to third-party sites.",
                       recommendation=rec)
    effective = [v.strip().lower() for v in value.split(",") if v.strip()][-1:]
    if effective and effective[0] in ("unsafe-url", "no-referrer-when-downgrade"):
        return Finding(**base, status=Status.WARN, severity=Severity.LOW,
                       detail=f"'{effective[0]}' sends the full URL to other sites.", recommendation=rec, evidence=value)
    return Finding(**base, status=Status.PASS, severity=Severity.LOW,
                   detail="Referrer information is limited.", evidence=value)


def check_permissions_policy(value: str | None) -> Finding:
    base = dict(check_id="headers.permissions", category=CAT, title="Permissions-Policy",
                reference="https://developer.mozilla.org/docs/Web/HTTP/Headers/Permissions-Policy")
    if value:
        return Finding(**base, status=Status.PASS, severity=Severity.LOW,
                       detail="Browser features (camera, microphone, geolocation...) are restricted.", evidence=value[:200])
    return Finding(**base, status=Status.FAIL, severity=Severity.LOW,
                   detail="Embedded or injected content may request powerful browser features like camera or geolocation.",
                   recommendation="Add e.g.: Permissions-Policy: camera=(), microphone=(), geolocation=()")


def run(resp: HttpResponse) -> list[Finding]:
    csp = resp.header("content-security-policy")
    findings = []
    if resp.is_https:
        findings.append(check_hsts(resp.header("strict-transport-security")))
    findings += [
        check_csp(csp, resp.header("content-security-policy-report-only")),
        check_clickjacking(resp.header("x-frame-options"), csp),
        check_nosniff(resp.header("x-content-type-options")),
        check_referrer_policy(resp.header("referrer-policy")),
        check_permissions_policy(resp.header("permissions-policy")),
    ]
    return findings
