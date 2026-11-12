"""Domain-level checks: SPF and DMARC (email spoofing) and CAA (certificate issuance)."""
from __future__ import annotations

import ipaddress
import re
from typing import Callable

from .. import dns
from ..models import Finding, Severity, Status

CAT = "Email & DNS"
Resolver = Callable[[str, int], dns.DNSResponse]


def org_domain(host: str) -> str | None:
    """Best-effort registrable domain: strips 'www.'. Returns None for IPs/localhost."""
    host = host.strip(".").lower()
    try:
        ipaddress.ip_address(host)
        return None
    except ValueError:
        pass
    if "." not in host or host.endswith((".localhost", ".test", ".local")):
        return None
    return host[4:] if host.startswith("www.") else host


def parents(host: str, stop: str) -> list[str]:
    """host and each parent domain up to (and including) stop."""
    labels = host.strip(".").lower().split(".")
    out = []
    for i in range(len(labels)):
        name = ".".join(labels[i:])
        out.append(name)
        if name == stop:
            break
    return out


def check_spf(records: list[str]) -> Finding:
    title = "SPF record (email sender policy)"
    ref = "https://www.cloudflare.com/learning/dns/dns-records/dns-spf-record/"
    spf = [r for r in records if r.lower().startswith("v=spf1")]
    if not spf:
        return Finding("dns.spf", CAT, title, Status.FAIL, Severity.MEDIUM,
                       "No SPF record, so mail servers can't tell which servers may send email for this domain. "
                       "That makes spoofed phishing emails easier.",
                       'Publish a TXT record such as: v=spf1 include:_spf.google.com -all '
                       '(or "v=spf1 -all" if the domain never sends email).', reference=ref)
    if len(spf) > 1:
        return Finding("dns.spf", CAT, title, Status.FAIL, Severity.MEDIUM,
                       "Multiple SPF records exist. That is invalid (RFC 7208), so receivers ignore SPF entirely.",
                       "Merge them into a single v=spf1 record.", evidence=" | ".join(spf), reference=ref)
    record = spf[0]
    m = re.search(r"(?:^|\s)([+?~-]?)all\b", record, re.I)
    qualifier = m.group(1) if m else None
    if qualifier in ("", "+"):
        return Finding("dns.spf", CAT, title, Status.FAIL, Severity.HIGH,
                       '"+all" authorises the whole internet to send mail as this domain.',
                       "Replace +all with -all (or ~all).", evidence=record, reference=ref)
    if qualifier == "?":
        return Finding("dns.spf", CAT, title, Status.WARN, Severity.LOW,
                       '"?all" is neutral, so unauthorised senders are not penalised.',
                       "Use ~all or -all.", evidence=record, reference=ref)
    if qualifier is None and "redirect=" not in record.lower():
        return Finding("dns.spf", CAT, title, Status.WARN, Severity.LOW,
                       "The SPF record has no 'all' mechanism, so mail from other servers is not rejected.",
                       "End the record with -all or ~all.", evidence=record, reference=ref)
    return Finding("dns.spf", CAT, title, Status.PASS, Severity.MEDIUM,
                   "SPF defines which servers may send email for this domain.", evidence=record, reference=ref)


def check_dmarc(records: list[str], domain: str) -> Finding:
    title = "DMARC policy (anti-spoofing)"
    ref = "https://dmarc.org/overview/"
    dmarc = [r for r in records if r.lower().replace(" ", "").startswith("v=dmarc1")]
    if not dmarc:
        return Finding("dns.dmarc", CAT, title, Status.FAIL, Severity.MEDIUM,
                       "No DMARC record, so receivers have no instruction to reject emails that fake this domain.",
                       f"Add a TXT record at _dmarc.{domain}: v=DMARC1; p=quarantine; rua=mailto:dmarc@{domain}",
                       reference=ref)
    record = dmarc[0]
    m = re.search(r"\bp\s*=\s*(\w+)", record, re.I)
    policy = m.group(1).lower() if m else "none"
    if policy == "none":
        return Finding("dns.dmarc", CAT, title, Status.WARN, Severity.LOW,
                       "DMARC is in monitoring mode (p=none): spoofed emails are reported but still delivered.",
                       "After reviewing reports, move to p=quarantine and then p=reject.", evidence=record, reference=ref)
    return Finding("dns.dmarc", CAT, title, Status.PASS, Severity.MEDIUM,
                   f"DMARC tells receivers to {'reject' if policy == 'reject' else 'quarantine'} spoofed email.",
                   evidence=record, reference=ref)


def check_caa(records: list[tuple[int, str, str]], found_at: str | None) -> Finding:
    title = "CAA record (who may issue certificates)"
    ref = "https://letsencrypt.org/docs/caa/"
    issuers = sorted({v for _f, tag, v in records if tag in ("issue", "issuewild") and v})
    if not issuers:
        return Finding("dns.caa", CAT, title, Status.FAIL, Severity.INFO,
                       "No CAA record: any certificate authority may issue certificates for this domain.",
                       'Add a CAA record limiting issuance, e.g. 0 issue "letsencrypt.org".', reference=ref)
    return Finding("dns.caa", CAT, title, Status.PASS, Severity.INFO,
                   f"Only {', '.join(issuers)} may issue certificates.", evidence=f"at {found_at}", reference=ref)


def run(host: str, resolver: Resolver | None = None, timeout: float = 3.0) -> list[Finding]:
    domain = org_domain(host)
    if domain is None:
        return []
    resolve: Resolver = resolver or (lambda name, qtype: dns.query(name, qtype, timeout=timeout))
    findings: list[Finding] = []
    try:
        findings.append(check_spf(resolve(domain, dns.TYPE_TXT).txt()))
        findings.append(check_dmarc(resolve(f"_dmarc.{domain}", dns.TYPE_TXT).txt(), domain))
        caa, found_at = [], None
        for name in parents(host, domain):  # CAA is inherited from parent domains
            caa = resolve(name, dns.TYPE_CAA).caa()
            if caa:
                found_at = name
                break
        findings.append(check_caa(caa, found_at))
    except dns.DNSError as exc:
        findings.append(Finding("dns.lookup", CAT, "DNS lookups", Status.INFO, Severity.INFO,
                                f"Email/DNS checks skipped: {exc}. (Outbound DNS to public resolvers may be blocked.)"))
    return findings
