"""Compare a scan with an earlier one (a JSON report) to spot regressions."""
from __future__ import annotations

from dataclasses import dataclass

from .models import ScanResult

# Higher is better. INFO is neutral, so moving to or from it is never a regression.
STATUS_RANK = {"fail": 0, "warn": 1, "pass": 2}


@dataclass
class Change:
    check_id: str
    title: str
    before: str
    after: str


@dataclass
class Diff:
    old_score: int
    new_score: int
    old_grade: str
    new_grade: str
    regressions: list[Change]
    improvements: list[Change]
    new_checks: list[Change]

    @property
    def has_regressions(self) -> bool:
        return bool(self.regressions)


def compare(baseline: dict, current: ScanResult) -> Diff:
    """baseline is a dict produced by `sitesentry ... --json` (ScanResult.to_dict())."""
    old = {f["check_id"]: f for f in baseline.get("findings", []) if isinstance(f, dict) and "check_id" in f}
    regressions: list[Change] = []
    improvements: list[Change] = []
    new_checks: list[Change] = []
    for f in current.findings:
        before = old.get(f.check_id)
        after = f.status.value
        if before is None:
            if after in ("fail", "warn"):
                new_checks.append(Change(f.check_id, f.title, "-", after))
            continue
        b, a = STATUS_RANK.get(str(before.get("status"))), STATUS_RANK.get(after)
        if b is None or a is None or a == b:
            continue
        change = Change(f.check_id, f.title, str(before.get("status")), after)
        (improvements if a > b else regressions).append(change)
    return Diff(int(baseline.get("score", 0)), current.score, str(baseline.get("grade", "?")), current.grade,
                regressions, improvements, new_checks)


def to_text(diff: Diff) -> str:
    delta = diff.new_score - diff.old_score
    sign = "+" if delta > 0 else ""
    lines = ["", "  Compared with baseline",
             f"    Score : {diff.old_score} -> {diff.new_score} ({sign}{delta})   Grade: {diff.old_grade} -> {diff.new_grade}"]
    sections = [("Regressions", diff.regressions), ("Improvements", diff.improvements),
                ("New issues (not in baseline)", diff.new_checks)]
    for title, changes in sections:
        if changes:
            lines.append(f"    {title}:")
            lines += [f"      {c.before.upper():>4} -> {c.after.upper():<4}  {c.title}" for c in changes]
    if not (diff.regressions or diff.improvements or diff.new_checks):
        lines.append("    No changes.")
    return "\n".join(lines) + "\n"
