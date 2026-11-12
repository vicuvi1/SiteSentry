"""Command-line interface."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__, report
from .scanner import ScanError, scan

GRADE_ORDER = ["F", "D", "C", "B", "A", "A+"]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="sitesentry",
        description="Passive website security scanner: HTTPS, TLS, security headers, cookies, CORS and leaks.",
        epilog="Examples:\n  sitesentry example.com\n  sitesentry example.com --html report.html\n"
               "  sitesentry --serve            (opens the web interface)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("target", nargs="?", help="website to scan, e.g. example.com or https://example.com/login")
    p.add_argument("--serve", action="store_true", help="start the local web interface")
    p.add_argument("--port", type=int, default=8765, help="port for --serve (default 8765)")
    p.add_argument("--no-browser", action="store_true", help="with --serve: don't open a browser automatically")
    p.add_argument("--html", metavar="FILE", help="write a standalone HTML report")
    p.add_argument("--json", metavar="FILE", help="write results as JSON ('-' for stdout)")
    p.add_argument("--ports", action="store_true",
                   help="also check commonly abused service ports (only on hosts you own)")
    p.add_argument("--timeout", type=float, default=10.0, help="network timeout in seconds (default 10)")
    p.add_argument("--fail-under", metavar="GRADE", choices=GRADE_ORDER,
                   help="exit with code 1 if the grade is below this (for CI pipelines)")
    p.add_argument("--no-color", action="store_true", help="disable coloured output")
    p.add_argument("--version", action="version", version=f"SiteSentry {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.serve:
        from .web import serve
        serve(port=args.port, open_browser=not args.no_browser, timeout=args.timeout)
        return 0
    if not args.target:
        build_parser().print_help()
        return 2

    quiet = args.json == "-"
    log = (lambda _m: None) if quiet else (lambda m: print(f"  ... {m}", file=sys.stderr, flush=True))
    try:
        result = scan(args.target, timeout=args.timeout, check_ports=args.ports, log=log)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except ScanError as exc:
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

    if args.fail_under and GRADE_ORDER.index(result.grade) < GRADE_ORDER.index(args.fail_under):
        if not quiet:
            print(f"  Grade {result.grade} is below required {args.fail_under}.", file=sys.stderr)
        return 1
    return 0
