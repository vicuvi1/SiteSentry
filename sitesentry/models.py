"""Core data structures shared by every check."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def weight(self) -> int:
        """Points removed from the 100-point score when a check fails."""
        return {"critical": 30, "high": 15, "medium": 8, "low": 3, "info": 0}[self.value]

    @property
    def rank(self) -> int:
        """Sort key: lower number = more severe."""
        return ["critical", "high", "medium", "low", "info"].index(self.value)


class Status(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    WARN = "warn"
    INFO = "info"


@dataclass
class Finding:
    check_id: str
    category: str
    title: str
    status: Status
    severity: Severity
    detail: str
    recommendation: str = ""
    evidence: str = ""
    reference: str = ""

    @property
    def is_problem(self) -> bool:
        return self.status in (Status.FAIL, Status.WARN)

    def to_dict(self) -> dict:
        return {
            "check_id": self.check_id,
            "category": self.category,
            "title": self.title,
            "status": self.status.value,
            "severity": self.severity.value,
            "detail": self.detail,
            "recommendation": self.recommendation,
            "evidence": self.evidence,
            "reference": self.reference,
        }


@dataclass
class ScanResult:
    target: str
    final_url: str
    started_at: str
    duration_seconds: float
    findings: list[Finding] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    score: int = 0
    grade: str = "F"

    @property
    def problems(self) -> list[Finding]:
        return sorted(
            (f for f in self.findings if f.is_problem),
            key=lambda f: (f.severity.rank, f.status != Status.FAIL, f.title),
        )

    def counts(self) -> dict[str, int]:
        out = {s.value: 0 for s in Status}
        for f in self.findings:
            out[f.status.value] += 1
        return out

    def to_dict(self) -> dict:
        return {
            "tool": "SiteSentry",
            "target": self.target,
            "final_url": self.final_url,
            "started_at": self.started_at,
            "duration_seconds": round(self.duration_seconds, 2),
            "score": self.score,
            "grade": self.grade,
            "counts": self.counts(),
            "notes": self.notes,
            "findings": [f.to_dict() for f in self.findings],
        }
