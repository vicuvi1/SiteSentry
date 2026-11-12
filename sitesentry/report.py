"""Output formats: terminal, JSON and standalone HTML report."""
from __future__ import annotations

import json
import os
import sys
from importlib import resources

from .models import ScanResult, Status

PLACEHOLDER = "<!--REPORT_DATA-->"
CATEGORY_ORDER = ["Transport", "TLS", "Security headers", "Cookies", "CORS",
                  "Information disclosure", "Email & DNS", "Exposed services", "Best practice"]


def ui_page() -> str:
    return resources.files("sitesentry").joinpath("ui/index.html").read_text(encoding="utf-8")


def to_json(result: ScanResult) -> str:
    return json.dumps(result.to_dict(), indent=2)


def to_html(result: ScanResult) -> str:
    """Self-contained report: the web UI page with the scan data embedded."""
    data = json.dumps(result.to_dict()).replace("<", "\\u003c")  # can't break out of <script>
    return ui_page().replace(PLACEHOLDER, f"<script>window.__SITESENTRY_REPORT__={data};</script>", 1)


def to_compare_html(a: ScanResult, b: ScanResult) -> str:
    """Self-contained side-by-side comparison report."""
    data = json.dumps([a.to_dict(), b.to_dict()]).replace("<", "\\u003c")  # can't break out of <script>
    return ui_page().replace(PLACEHOLDER, f"<script>window.__SITESENTRY_COMPARE__={data};</script>", 1)


def compare_console(a: ScanResult, b: ScanResult) -> str:
    ca, cb = a.category_scores(), b.category_scores()
    ha, hb = a.final_url.split("/")[2], b.final_url.split("/")[2]
    w = max(len(ha), len(hb), 8)
    lines = ["", "SiteSentry comparison  -  made by Victor Barbuta", "",
             f"  {'':<24} {ha:>{w}}   {hb:>{w}}",
             f"  {'Grade':<24} {a.grade:>{w}}   {b.grade:>{w}}",
             f"  {'Score':<24} {a.score:>{w}}   {b.score:>{w}}", ""]
    cats = sorted(set(ca) | set(cb), key=lambda k: CATEGORY_ORDER.index(k) if k in CATEGORY_ORDER else 99)
    for cat in cats:
        x, y = ca.get(cat), cb.get(cat)
        mark_x = " *" if x is not None and y is not None and x > y else "  "
        mark_y = " *" if x is not None and y is not None and y > x else "  "
        sx = "-" if x is None else str(x)
        sy = "-" if y is None else str(y)
        lines.append(f"  {cat:<24} {sx:>{w}}{mark_x} {sy:>{w}}{mark_y}")
    winner = ha if a.score > b.score else hb if b.score > a.score else None
    lines += ["", f"  {'Winner: ' + winner if winner else 'Tie'}   (* = better in that category)", ""]
    return "\n".join(lines)


# ---------------------------------------------------------------- terminal --

def _use_color(stream) -> bool:
    return hasattr(stream, "isatty") and stream.isatty() and "NO_COLOR" not in os.environ


def to_console(result: ScanResult, color: bool | None = None) -> str:
    color = _use_color(sys.stdout) if color is None else color

    def c(code: str, text: str) -> str:
        return f"\033[{code}m{text}\033[0m" if color else text

    status_style = {
        Status.PASS: ("32", "PASS"), Status.FAIL: ("31", "FAIL"),
        Status.WARN: ("33", "WARN"), Status.INFO: ("90", "INFO"),
    }
    grade_code = "32" if result.grade.startswith("A") else "33" if result.grade in ("B", "C") else "31"
    counts = result.counts()

    lines = [
        "",
        c("1", "SiteSentry scan report") + c("90", "  -  made by Victor Barbuta"),
        f"  Target : {result.final_url}",
        f"  Time   : {result.started_at} ({result.duration_seconds:.1f}s)",
        f"  Grade  : {c('1;' + grade_code, result.grade)}  ({result.score}/100)",
        f"  Checks : {counts['pass']} passed, {counts['warn']} warnings, {counts['fail']} failed",
        "",
        c("1", "  Security profile"),
    ]
    profile = result.category_scores()
    for cat in sorted(profile, key=lambda k: CATEGORY_ORDER.index(k) if k in CATEGORY_ORDER else 99):
        value = profile[cat]
        bar = "#" * round(value / 5)
        code = "32" if value >= 85 else "33" if value >= 55 else "31"
        lines.append(f"    {cat:<24} {c(code, f'{bar:<20}')} {value:>3}")
    lines.append("")
    category = None
    order = {Status.FAIL: 0, Status.WARN: 1, Status.INFO: 2, Status.PASS: 3}

    def cat_rank(name: str) -> int:
        return CATEGORY_ORDER.index(name) if name in CATEGORY_ORDER else len(CATEGORY_ORDER)

    for f in sorted(result.findings, key=lambda f: (cat_rank(f.category), order[f.status], f.severity.rank)):
        if f.category != category:
            category = f.category
            lines.append(c("1;36", f"  {category}"))
        code, label = status_style[f.status]
        sev = f" [{f.severity.value}]" if f.is_problem and f.severity.value != "info" else ""
        lines.append(f"    {c(code, label)}  {f.title}{c('90', sev)}")
        if f.is_problem:
            lines.append(c("90", f"          {f.detail}"))
            if f.recommendation:
                lines.append(f"          -> {f.recommendation}")
    if result.notes:
        lines += ["", c("90", "  Notes:")] + [c("90", f"    - {n}") for n in result.notes]
    lines.append("")
    return "\n".join(lines)
