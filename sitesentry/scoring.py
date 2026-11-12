"""Turn findings into a 0-100 score and an A+ to F grade."""
from __future__ import annotations

from .models import Finding, Severity, Status

GRADES = [(95, "A+"), (85, "A"), (70, "B"), (55, "C"), (40, "D"), (0, "F")]


def penalty(finding: Finding) -> int:
    if finding.status == Status.FAIL:
        return finding.severity.weight
    if finding.status == Status.WARN:
        return (finding.severity.weight + 1) // 2  # warnings cost half
    return 0


def score(findings: list[Finding]) -> tuple[int, str]:
    value = max(0, 100 - sum(penalty(f) for f in findings))
    grade = next(letter for floor, letter in GRADES if value >= floor)
    if any(f.status == Status.FAIL and f.severity == Severity.CRITICAL for f in findings):
        grade = "F"  # no HTTPS / broken certificate can't be "average"
    return value, grade


def category_scores(findings: list[Finding]) -> dict[str, int]:
    """Per-category 0-100 score: the weighted share of checks that pass (warnings count half).

    Every check weighs at least 1, so informational checks (e.g. security.txt) still count.
    INFO results are neutral and left out.
    """
    totals: dict[str, list[float]] = {}
    for f in findings:
        if f.status == Status.INFO:
            continue
        weight = max(f.severity.weight, 1)
        earned = weight if f.status == Status.PASS else weight / 2 if f.status == Status.WARN else 0
        bucket = totals.setdefault(f.category, [0.0, 0.0])
        bucket[0] += earned
        bucket[1] += weight
    return {cat: round(100 * earned / total) for cat, (earned, total) in totals.items() if total}
