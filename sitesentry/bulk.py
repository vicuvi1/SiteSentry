"""Scan many sites at once: sitesentry --list sites.txt [--csv out.csv]"""
from __future__ import annotations

import csv
import io
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

from .models import ScanResult, Severity, Status
from .scanner import ScanError, scan

MAX_SITES = 500


@dataclass
class BulkItem:
    target: str
    result: ScanResult | None = None
    error: str = ""


def read_targets(path: str) -> list[str]:
    """One site per line; blank lines and # comments are ignored; duplicates removed."""
    lines = Path(path).read_text(encoding="utf-8").splitlines()
    targets = [ln.split("#", 1)[0].strip() for ln in lines]
    unique = list(dict.fromkeys(t for t in targets if t))
    if len(unique) > MAX_SITES:
        raise ValueError(f"{path} lists {len(unique)} sites; the maximum is {MAX_SITES}.")
    return unique


def scan_many(targets: list[str], *, workers: int = 6, progress: Callable[[BulkItem], None] | None = None,
              **scan_kwargs) -> list[BulkItem]:
    def one(target: str) -> BulkItem:
        try:
            item = BulkItem(target, result=scan(target, **scan_kwargs))
        except (ScanError, ValueError) as exc:
            item = BulkItem(target, error=str(exc))
        if progress:
            progress(item)
        return item

    with ThreadPoolExecutor(max_workers=max(1, min(workers, 16))) as pool:
        return list(pool.map(one, targets))  # keeps the input order


def _critical_and_high(result: ScanResult) -> int:
    return sum(1 for f in result.findings if f.status == Status.FAIL and f.severity in (Severity.CRITICAL, Severity.HIGH))


def to_csv(items: list[BulkItem]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")  # write_text adds \r on Windows: avoid blank rows
    w.writerow(["target", "final_url", "grade", "score", "failed", "warnings", "critical_or_high", "error"])
    for it in items:
        if it.result:
            c = it.result.counts()
            w.writerow([it.target, it.result.final_url, it.result.grade, it.result.score,
                        c["fail"], c["warn"], _critical_and_high(it.result), ""])
        else:
            w.writerow([it.target, "", "", "", "", "", "", it.error])
    return buf.getvalue()


def to_table(items: list[BulkItem]) -> str:
    scanned = sorted(((i.target, i.result) for i in items if i.result is not None), key=lambda p: -p[1].score)
    width = max([len(i.target) for i in items] + [6])
    lines = ["", f"  {'Site':<{width}}  Grade  Score  Failed", f"  {'-' * width}  -----  -----  ------"]
    for target, r in scanned:
        lines.append(f"  {target:<{width}}  {r.grade:>5}  {r.score:>5}  {r.counts()['fail']:>6}")
    for it in (i for i in items if i.result is None):
        lines.append(f"  {it.target:<{width}}  error: {it.error[:70]}")
    if scanned:
        avg = sum(r.score for _, r in scanned) / len(scanned)
        lines += ["", f"  {len(scanned)}/{len(items)} scanned, average score {avg:.0f}/100"]
    return "\n".join(lines) + "\n"
