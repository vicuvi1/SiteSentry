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
