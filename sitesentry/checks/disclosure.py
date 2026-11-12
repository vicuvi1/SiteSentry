"""Information disclosure through response headers."""
from __future__ import annotations

import re

from ..models import Finding, Severity, Status
from ..net import HttpResponse

CAT = "Information disclosure"
TECH_HEADERS = ("x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator", "x-drupal-cache", "x-runtime")
VERSION_RE = re.compile(r"\d+(?:\.\d+)+|/\d")


def run(chain: list[HttpResponse]) -> list[Finding]:
    findings: list[Finding] = []

    server = next((r.header("server") for r in chain if r.header("server")), None)
    if server and VERSION_RE.search(server):
        findings.append(Finding(
            "disclosure.server", CAT, "Server version banner", Status.FAIL, Severity.LOW,
            "The Server header reveals software and version, which helps attackers look up known exploits (CVEs).",
            "Hide the version (e.g. nginx: server_tokens off; Apache: ServerTokens Prod).",
            evidence=f"Server: {server}",
            reference="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server",
        ))
    else:
        findings.append(Finding(
            "disclosure.server", CAT, "Server version banner", Status.PASS, Severity.LOW,
            "No software version is exposed in the Server header.",
            evidence=f"Server: {server}" if server else "",
        ))

    leaked = []
    for resp in chain:
        for name in TECH_HEADERS:
            value = resp.header(name)
            if value and f"{name}: {value}" not in leaked:
                leaked.append(f"{name}: {value}")
    if leaked:
        findings.append(Finding(
            "disclosure.tech", CAT, "Technology fingerprint headers", Status.FAIL, Severity.LOW,
            "Headers reveal the framework or language behind the site.",
            "Remove these headers in the web server or framework configuration.",
            evidence="; ".join(leaked),
        ))
    else:
        findings.append(Finding(
            "disclosure.tech", CAT, "Technology fingerprint headers", Status.PASS, Severity.LOW,
            "No X-Powered-By style headers found.",
        ))
    return findings
