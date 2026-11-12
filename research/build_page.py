"""Build docs/research.html from research/results.json.

Usage:  python research/build_page.py
"""
from __future__ import annotations

import html
import json
import statistics
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA = json.loads((ROOT / "research" / "results.json").read_text(encoding="utf-8"))
OK = [s for s in DATA["sites"] if "grade" in s]
FAILED = [s for s in DATA["sites"] if "error" in s]
GRADES = ["A+", "A", "B", "C", "D", "F"]


def st(site: dict, check: str) -> str | None:
    c = site["checks"].get(check)
    return c["status"] if c else None


def ev(site: dict, check: str) -> str:
    return site["checks"].get(check, {}).get("evidence", "")


# (label, plain-English meaning, predicate -> True/False/None (None = not applicable))
CONTROLS = [
    ("Redirects HTTP to HTTPS", "Visitors typing http:// are moved to the encrypted site.",
     lambda s: st(s, "transport.redirect") == "pass"),
    ("TLS 1.3", "Uses the newest, fastest and most secure TLS version.",
     lambda s: ev(s, "tls.version").startswith("TLSv1.3") if st(s, "tls.version") else None),
    ("Legacy TLS 1.0/1.1 refused", "Deprecated protocol versions are switched off.",
     lambda s: None if st(s, "tls.legacy") in (None, "info") else st(s, "tls.legacy") == "pass"),
    ("HSTS enabled", "Browsers are told to always use HTTPS.",
     lambda s: st(s, "headers.hsts") in ("pass", "warn")),
    ("Clickjacking protection", "Other sites can't frame the page invisibly.",
     lambda s: st(s, "headers.clickjacking") == "pass"),
    ("X-Content-Type-Options", "MIME-type sniffing is disabled.",
     lambda s: st(s, "headers.nosniff") == "pass"),
    ("Referrer-Policy", "Full URLs don't leak to third parties.",
     lambda s: st(s, "headers.referrer") == "pass"),
    ("Content-Security-Policy (any)", "Has some policy limiting where scripts load from.",
     lambda s: st(s, "headers.csp") in ("pass", "warn")),
    ("Strong CSP", "CSP without 'unsafe-inline', 'unsafe-eval' or wildcards.",
     lambda s: st(s, "headers.csp") == "pass"),
    ("Permissions-Policy", "Camera, microphone and location access are restricted.",
     lambda s: st(s, "headers.permissions") == "pass"),
    ("Server version hidden", "No software version in the Server header.",
     lambda s: st(s, "disclosure.server") == "pass"),
    ("SPF record", "Declares which servers may send its email.",
     lambda s: st(s, "dns.spf") in ("pass", "warn") if st(s, "dns.spf") else None),
    ("DMARC enforced", "Spoofed email is quarantined or rejected (not just monitored).",
     lambda s: st(s, "dns.dmarc") == "pass" if st(s, "dns.dmarc") else None),
    ("CAA record", "Limits which authorities may issue its certificates.",
     lambda s: st(s, "dns.caa") == "pass" if st(s, "dns.caa") else None),
    ("security.txt", "Publishes a contact for reporting vulnerabilities.",
     lambda s: st(s, "misc.securitytxt") == "pass"),
]


def rate(pred) -> tuple[int, int]:
    vals = [pred(s) for s in OK]
    applicable = [v for v in vals if v is not None]
    return sum(1 for v in applicable if v), len(applicable)


def pct(n: int, d: int) -> int:
    return round(100 * n / d) if d else 0


rates = [(label, meaning, *rate(pred)) for label, meaning, pred in CONTROLS]
rates.sort(key=lambda r: -pct(r[2], r[3]))
by_label = {r[0]: r for r in rates}

grade_counts = Counter(s["grade"] for s in OK)
scores = [s["score"] for s in OK]
median = statistics.median(scores)
a_or_better = sum(grade_counts[g] for g in ("A+", "A"))
no_csp = sum(1 for s in OK if st(s, "headers.csp") == "fail")
csp_any_n, csp_any_d = by_label["Content-Security-Policy (any)"][2:4]
strong_n, _ = by_label["Strong CSP"][2:4]
legacy_ok, legacy_d = by_label["Legacy TLS 1.0/1.1 refused"][2:4]
dmarc_n, dmarc_d = by_label["DMARC enforced"][2:4]
sectxt_n, sectxt_d = by_label["security.txt"][2:4]
perm_n, perm_d = by_label["Permissions-Policy"][2:4]
n = len(OK)

# ---------------------------------------------------------------- HTML parts --

esc = html.escape


def tile(value: str, label: str, sub: str) -> str:
    return f'<div class="tile"><b>{value}</b><span>{label}</span><small>{sub}</small></div>'


tiles = "".join([
    tile(f"{median:g}", "median score", f"out of 100 across {n} sites"),
    tile(f"{pct(a_or_better, n)}%", "earn an A or A+", f"{a_or_better} of {n} sites"),
    tile(f"{pct(no_csp, n)}%", "have no CSP at all", "the main browser defence against XSS"),
    tile(f"{pct(legacy_d - legacy_ok, legacy_d)}%", "still accept TLS 1.0/1.1", "protocols deprecated in 2021"),
])

max_grade = max(grade_counts.values())
grade_bars = "".join(
    f'<div class="vcol"><div class="vval">{grade_counts[g]}</div>'
    f'<div class="vbar" style="height:{max(2, 100 * grade_counts[g] / max_grade):.1f}%" '
    f'data-tip="Grade {g}: {grade_counts[g]} of {n} sites ({pct(grade_counts[g], n)}%)"></div>'
    f'<div class="vlab">{g}</div></div>'
    for g in GRADES
)

control_rows = "".join(
    f'<div class="hrow" data-tip="{esc(label)}: {num} of {den} sites ({pct(num, den)}%). {esc(meaning)}">'
    f'<div class="hlab">{esc(label)}</div>'
    f'<div class="htrack"><div class="hbar" style="width:{max(0.6, pct(num, den))}%"></div>'
    f'<span class="hval">{pct(num, den)}%</span></div></div>'
    for label, meaning, num, den in rates
)

GRADE_CLASS = {"A+": "g-a", "A": "g-a", "B": "g-b", "C": "g-c", "D": "g-d", "F": "g-f"}


def mark(v: bool | None) -> str:
    if v is None:
        return '<td class="na" title="Not applicable">–</td>'
    return '<td class="yes" title="Yes">✓</td>' if v else '<td class="no" title="No">✗</td>'


TABLE_COLS = [("HSTS", CONTROLS[3][2]), ("CSP", CONTROLS[7][2]), ("TLS 1.3", CONTROLS[1][2]),
              ("No legacy TLS", CONTROLS[2][2]), ("DMARC enforced", CONTROLS[12][2]), ("security.txt", CONTROLS[14][2])]
rows = "".join(
    f'<tr><td class="site">{esc(s["site"])}</td>'
    f'<td data-sort="{s["score"]}"><span class="grade {GRADE_CLASS[s["grade"]]}">{esc(s["grade"])}</span></td>'
    f'<td data-sort="{s["score"]}">{s["score"]}</td>'
    + "".join(mark(fn(s)) for _, fn in TABLE_COLS) + "</tr>"
    for s in sorted(OK, key=lambda s: (-s["score"], s["site"]))
)
rows += "".join(
    f'<tr class="err"><td class="site">{esc(s["site"])}</td><td data-sort="-1" colspan="{2 + len(TABLE_COLS)}">'
    "Not scanned: the site didn't respond to automated requests.</td></tr>" for s in FAILED
)
head = "".join(f"<th>{esc(h)}</th>" for h, _ in TABLE_COLS)

findings = [
    f"<b>Only {pct(a_or_better, n)}% earn an A or better.</b> The typical site scores {median:g}/100 (grade "
    f"{next(g for floor, g in [(95, 'A+'), (85, 'A'), (70, 'B'), (55, 'C'), (40, 'D'), (0, 'F')] if median >= floor)}). "
    "HTTPS is universal, but the extra layers that limit damage when something goes wrong are not.",
    f"<b>{pct(no_csp, n)}% have no Content-Security-Policy at all</b>, and only {pct(strong_n, n)}% have a strong one. "
    f"Of the {csp_any_n} sites with a CSP, {csp_any_n - strong_n} weaken it with 'unsafe-inline', 'unsafe-eval' or wildcards.",
    f"<b>{pct(legacy_d - legacy_ok, legacy_d)}% still accept TLS 1.0 or 1.1</b>, protocol versions formally deprecated by "
    "RFC 8996 in 2021. Often this is kept for old devices, but it widens the attack surface.",
    f"<b>Email is the best-defended area: {pct(by_label['SPF record'][2], by_label['SPF record'][3])}% publish SPF and "
    f"{pct(dmarc_n, dmarc_d)}% enforce DMARC.</b> Big brands are prime phishing targets, and it shows. The browser-side "
    "headers that protect visitors lag far behind.",
    f"<b>{pct(sectxt_n, sectxt_d)}% publish a security.txt</b> and {pct(perm_n, perm_d)}% set a Permissions-Policy: "
    "the cheapest wins on this list, at a few lines of config each.",
]

page = (ROOT / "research" / "template.html").read_text(encoding="utf-8")
for key, value in {
    "{{DATE}}": esc(DATA["scanned_at"]),
    "{{TOOL}}": esc(DATA["tool"]),
    "{{N}}": str(n),
    "{{TOTAL}}": str(len(DATA["sites"])),
    "{{TILES}}": tiles,
    "{{FINDINGS}}": "".join(f"<li>{f}</li>" for f in findings),
    "{{GRADE_BARS}}": grade_bars,
    "{{CONTROL_ROWS}}": control_rows,
    "{{TABLE_HEAD}}": head,
    "{{TABLE_ROWS}}": rows,
}.items():
    page = page.replace(key, value)
(ROOT / "docs" / "research.html").write_text(page, encoding="utf-8")
print(f"docs/research.html written ({n} sites). Median {median:g}, A or better {pct(a_or_better, n)}%")
for label, _, num, den in rates:
    print(f"  {pct(num, den):3}%  {label}  ({num}/{den})")
