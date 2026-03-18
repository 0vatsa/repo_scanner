#!/usr/bin/env python3
# repo_scanner/__main__.py
"""
CLI entry point — allows both:
    python -m repo_scanner /path/to/repo
    python main.py /path/to/repo        (via the repo root shim)
"""

import argparse
import sys

from .scanner import run_scan
from .reporter import print_terminal_report, save_json_report


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="repo_scanner",
        description="Scan a repository for data-exfiltration risks and suspicious network calls.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m repo_scanner /path/to/repo
  python -m repo_scanner /path/to/repo --severity HIGH
  python -m repo_scanner /path/to/repo --output report.json
  python -m repo_scanner /path/to/repo --severity MEDIUM --output report.json
        """,
    )
    parser.add_argument(
        "repo",
        help="Path to the repository / folder to scan.",
    )
    parser.add_argument(
        "--severity",
        default="INFO",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
        help="Minimum severity to report (default: INFO — show everything).",
    )
    parser.add_argument(
        "--output",
        default=None,
        metavar="FILE",
        help="Optional path to save a JSON report.",
    )

    args = parser.parse_args()

    print(f"[*] Starting scan: {args.repo}  (min severity: {args.severity})")
    result = run_scan(args.repo, min_severity=args.severity)
    print_terminal_report(result)

    if args.output:
        save_json_report(result, args.output)


if __name__ == "__main__":
    main()
