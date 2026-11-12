"""Command-line interface."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __author__, __version__, report
from .scanner import ScanError, scan

GRADE_ORDER = ["F", "D", "C", "B", "A", "A+"]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="sitesentry",
        description="Passive website security scanner: HTTPS, TLS, security headers, cookies, CORS, email/DNS and leaks.",
        epilog="Examples:\n"
               "  sitesentry example.com\n"
               "  sitesentry example.com --html report.html --json report.json\n"
               "  sitesentry example.com --baseline report.json --fail-on-regression\n"
               "  sitesentry --list sites.txt --csv results.csv\n"
               "  sitesentry --compare staging.example.com example.com --html compare.html\n"
               "  sitesentry --serve                (opens the web interface)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("target", nargs="?", help="website to scan, e.g. example.com or https://example.com/login")

    g = p.add_argument_group("web interface")
    g.add_argument("--serve", action="store_true", help="start the local web interface")
    g.add_argument("--host", default="127.0.0.1", help="address for --serve (default 127.0.0.1; use 0.0.0.0 inside Docker)")
    g.add_argument("--port", type=int, default=8765, help="port for --serve (default 8765)")
    g.add_argument("--no-browser", action="store_true", help="don't open a browser automatically")
    g.add_argument("--allow-private", action="store_true",
                   help="allow scanning private/internal addresses (off by default: SSRF protection)")

    o = p.add_argument_group("output")
    o.add_argument("--html", metavar="FILE", help="write a standalone HTML report")
    o.add_argument("--json", metavar="FILE", help="write results as JSON ('-' for stdout)")
    o.add_argument("--csv", metavar="FILE", help="with --list: write a CSV summary")
    o.add_argument("--no-color", action="store_true", help="disable coloured output")

    s = p.add_argument_group("scanning")
    s.add_argument("--compare", nargs=2, metavar=("SITE_A", "SITE_B"), help="scan two sites and compare them side by side")
    s.add_argument("--list", metavar="FILE", help="scan every site listed in FILE (one per line, # comments allowed)")
    s.add_argument("--workers", type=int, default=6, help="with --list: parallel scans (default 6, max 16)")
    s.add_argument("--ports", action="store_true", help="also check commonly abused service ports (only on hosts you own)")
    s.add_argument("--no-dns", action="store_true", help="skip the SPF / DMARC / CAA DNS checks")
    s.add_argument("--timeout", type=float, default=10.0, help="network timeout in seconds (default 10)")

    c = p.add_argument_group("CI / automation")
    c.add_argument("--fail-under", metavar="GRADE", choices=GRADE_ORDER,
                   help="exit with code 1 if the grade (or any grade, with --list) is below this")
    c.add_argument("--baseline", metavar="FILE", help="compare with an earlier --json report and show what changed")
    c.add_argument("--fail-on-regression", action="store_true", help="with --baseline: exit 1 if any check got worse")

    p.add_argument("--version", action="version", version=f"SiteSentry {__version__}, made by {__author__}")
    return p


def below(grade: str, required: str | None) -> bool:
    return bool(required) and GRADE_ORDER.index(grade) < GRADE_ORDER.index(required)  # type: ignore[arg-type]


def run_bulk(args: argparse.Namespace) -> int:
    from . import bulk

    try:
        targets = bulk.read_targets(args.list)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if not targets:
        print(f"error: {args.list} contains no sites", file=sys.stderr)
        return 2

    done = 0

    def progress(item: bulk.BulkItem) -> None:
        nonlocal done
        done += 1
        status = f"{item.result.grade:>2} {item.result.score:>3}" if item.result else "error"
        print(f"  [{done:>3}/{len(targets)}] {status}  {item.target}", file=sys.stderr, flush=True)

    items = bulk.scan_many(targets, workers=args.workers, progress=progress, timeout=args.timeout,
                           check_ports=args.ports, check_dns=not args.no_dns)
    print(bulk.to_table(items))
    if args.csv:
        Path(args.csv).write_text(bulk.to_csv(items), encoding="utf-8")
        print(f"  CSV written to {args.csv}")
    if args.json:
        payload = [it.result.to_dict() if it.result else {"target": it.target, "error": it.error} for it in items]
        text = json.dumps(payload, indent=2)
        if args.json == "-":
            print(text)
        else:
            Path(args.json).write_text(text, encoding="utf-8")
            print(f"  JSON written to {args.json}")
    failing = [it for it in items if it.result and below(it.result.grade, args.fail_under)]
    if failing:
        print(f"  {len(failing)} site(s) below required grade {args.fail_under}.", file=sys.stderr)
        return 1
    return 0


def run_compare(args: argparse.Namespace) -> int:
    from .bulk import scan_many

    items = scan_many(list(args.compare), workers=2, timeout=args.timeout, check_ports=args.ports, check_dns=not args.no_dns)
    for it in items:
        if it.result is None:
            print(f"error: {it.target}: {it.error}", file=sys.stderr)
            return 2
    a, b = items[0].result, items[1].result
    assert a is not None and b is not None
    print(report.compare_console(a, b))
    if args.html:
        Path(args.html).write_text(report.to_compare_html(a, b), encoding="utf-8")
        print(f"  HTML comparison written to {args.html}")
    if args.json:
        text = json.dumps([a.to_dict(), b.to_dict()], indent=2)
        if args.json == "-":
            print(text)
        else:
            Path(args.json).write_text(text, encoding="utf-8")
    return 1 if below(a.grade, args.fail_under) or below(b.grade, args.fail_under) else 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.serve:
        from .web import serve
        serve(host=args.host, port=args.port, open_browser=not args.no_browser, timeout=args.timeout,
              allow_private=args.allow_private)
        return 0
    if args.list:
        return run_bulk(args)
    if args.compare:
        return run_compare(args)
    if not args.target:
        build_parser().print_help()
        return 2

    baseline = None
    if args.baseline:
        try:
            baseline = json.loads(Path(args.baseline).read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            print(f"error: can't read baseline: {exc}", file=sys.stderr)
            return 2

    quiet = args.json == "-"
    log = (lambda _m: None) if quiet else (lambda m: print(f"  ... {m}", file=sys.stderr, flush=True))
    try:
        result = scan(args.target, timeout=args.timeout, check_ports=args.ports,
                      check_dns=not args.no_dns, log=log)
    except (ValueError, ScanError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.json == "-":
        print(report.to_json(result))
    else:
        print(report.to_console(result, color=False if args.no_color else None))
        if args.json:
            Path(args.json).write_text(report.to_json(result), encoding="utf-8")
            print(f"  JSON written to {args.json}")
    if args.html:
        Path(args.html).write_text(report.to_html(result), encoding="utf-8")
        if not quiet:
            print(f"  HTML report written to {args.html}")

    code = 0
    if baseline is not None:
        from .diff import compare, to_text
        diff = compare(baseline, result)
        print(to_text(diff), file=sys.stderr if quiet else sys.stdout)
        if args.fail_on_regression and diff.has_regressions:
            print(f"  {len(diff.regressions)} check(s) regressed since the baseline.", file=sys.stderr)
            code = 1
    if below(result.grade, args.fail_under):
        if not quiet:
            print(f"  Grade {result.grade} is below required {args.fail_under}.", file=sys.stderr)
        code = 1
    return code
