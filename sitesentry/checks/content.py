"""Page content checks: mixed content on HTTPS pages."""
from __future__ import annotations

import re

from ..models import Finding, Severity, Status
from ..net import HttpResponse

CAT = "Transport"
TAG_RE = re.compile(r"<(script|iframe|img|audio|video|source|embed|link)\b[^>]*>", re.I)
SRC_RE = re.compile(r"""\b(?:src|href)\s*=\s*["']?(http://[^"'\s>]+)""", re.I)
ACTIVE = {"script", "iframe", "embed", "link"}


def find_mixed_content(html: str) -> tuple[list[str], list[str]]:
    """Return (active, passive) insecure URLs referenced by the page."""
    active: list[str] = []
    passive: list[str] = []
    for m in TAG_RE.finditer(html):
        tag, whole = m.group(1).lower(), m.group(0)
        if tag == "link" and "stylesheet" not in whole.lower():
            continue  # canonical/alternate links are not loaded by the browser
        src = SRC_RE.search(whole)
        if not src:
            continue
        (active if tag in ACTIVE else passive).append(src.group(1))
    return active, passive


def run(resp: HttpResponse) -> list[Finding]:
    ctype = (resp.header("content-type") or "").lower()
    if not resp.is_https or "html" not in ctype:
        return []
    active, passive = find_mixed_content(resp.text)
    ref = "https://developer.mozilla.org/docs/Web/Security/Mixed_content"
    if active:
        return [Finding("content.mixed", CAT, "Mixed content", Status.FAIL, Severity.MEDIUM,
                        f"The HTTPS page loads {len(active)} script/style/frame resource(s) over plain HTTP. "
                        "An attacker on the network could replace them with malicious code.",
                        "Load every resource over https:// (or use protocol-relative / same-origin paths).",
                        evidence=", ".join(active[:5]), reference=ref)]
    if passive:
        return [Finding("content.mixed", CAT, "Mixed content", Status.WARN, Severity.LOW,
                        f"The HTTPS page loads {len(passive)} image/media file(s) over plain HTTP.",
                        "Switch these URLs to https://.", evidence=", ".join(passive[:5]), reference=ref)]
    return [Finding("content.mixed", CAT, "Mixed content", Status.PASS, Severity.MEDIUM,
                    "No resources are loaded over plain HTTP.", reference=ref)]
