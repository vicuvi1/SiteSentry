"""Cookie security attributes: Secure, HttpOnly, SameSite."""
from __future__ import annotations

from dataclasses import dataclass, field

from ..models import Finding, Severity, Status
from ..net import HttpResponse

CAT = "Cookies"
REF = "https://owasp.org/www-community/controls/SecureCookieAttribute"


@dataclass
class Cookie:
    name: str
    attrs: dict[str, str] = field(default_factory=dict)

    @property
    def secure(self) -> bool:
        return "secure" in self.attrs

    @property
    def httponly(self) -> bool:
        return "httponly" in self.attrs

    @property
    def samesite(self) -> str | None:
        v = self.attrs.get("samesite")
        return v.lower() if v is not None else None

    @property
    def is_deletion(self) -> bool:
        return self.attrs.get("max-age", "").strip() in ("0", "-1")


def parse_set_cookie(header: str) -> Cookie:
    parts = [p.strip() for p in header.split(";")]
    name = parts[0].split("=", 1)[0].strip()
    attrs: dict[str, str] = {}
    for part in parts[1:]:
        if not part:
            continue
        key, _, value = part.partition("=")
        attrs[key.strip().lower()] = value.strip()
    return Cookie(name, attrs)


def _names(cookies: list[Cookie]) -> str:
    seen = sorted({c.name for c in cookies})
    shown = ", ".join(seen[:8])
    return shown + (f" (+{len(seen) - 8} more)" if len(seen) > 8 else "")


def analyze(cookies: list[Cookie]) -> list[Finding]:
    cookies = [c for c in cookies if not c.is_deletion]
    if not cookies:
        return [Finding("cookies.none", CAT, "Cookie flags", Status.INFO, Severity.INFO,
                        "The scanned page did not set any cookies.")]

    findings: list[Finding] = []

    no_secure = [c for c in cookies if not c.secure]
    findings.append(
        Finding("cookies.secure", CAT, "Cookie Secure flag", Status.FAIL, Severity.MEDIUM,
                "These cookies can be sent over unencrypted HTTP and stolen on public Wi-Fi.",
                "Add the Secure attribute to every cookie.", evidence=_names(no_secure), reference=REF)
        if no_secure else
        Finding("cookies.secure", CAT, "Cookie Secure flag", Status.PASS, Severity.MEDIUM,
                "All cookies are HTTPS-only.", evidence=_names(cookies), reference=REF)
    )

    no_httponly = [c for c in cookies if not c.httponly]
    findings.append(
        Finding("cookies.httponly", CAT, "Cookie HttpOnly flag", Status.WARN, Severity.LOW,
                "JavaScript can read these cookies, so an XSS bug could steal them. "
                "(Fine for non-sensitive cookies that scripts genuinely need.)",
                "Add HttpOnly to session and authentication cookies.", evidence=_names(no_httponly), reference=REF)
        if no_httponly else
        Finding("cookies.httponly", CAT, "Cookie HttpOnly flag", Status.PASS, Severity.LOW,
                "No cookie is readable from JavaScript.", reference=REF)
    )

    no_samesite = [c for c in cookies if c.samesite is None]
    none_insecure = [c for c in cookies if c.samesite == "none" and not c.secure]
    if none_insecure:
        findings.append(Finding("cookies.samesite", CAT, "Cookie SameSite attribute", Status.FAIL, Severity.MEDIUM,
                                "SameSite=None without Secure: browsers reject it, and it allows cross-site sending.",
                                "Use SameSite=Lax (or Strict); SameSite=None must be paired with Secure.",
                                evidence=_names(none_insecure), reference=REF))
    elif no_samesite:
        findings.append(Finding("cookies.samesite", CAT, "Cookie SameSite attribute", Status.WARN, Severity.LOW,
                                "No explicit SameSite; protection against cross-site request forgery (CSRF) depends on browser defaults.",
                                "Set SameSite=Lax or SameSite=Strict explicitly.", evidence=_names(no_samesite), reference=REF))
    else:
        findings.append(Finding("cookies.samesite", CAT, "Cookie SameSite attribute", Status.PASS, Severity.LOW,
                                "Every cookie declares a SameSite policy.", reference=REF))
    return findings


def run(chain: list[HttpResponse]) -> list[Finding]:
    cookies = [parse_set_cookie(h) for resp in chain for h in resp.header_all("set-cookie")]
    return analyze(cookies)
