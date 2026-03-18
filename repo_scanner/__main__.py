#!/usr/bin/env python3
# repo_scanner/__main__.py
"""
CLI entry point — allows both:
    python -m repo_scanner /path/to/repo
    python main.py /path/to/repo        (via the repo root shim)
"""

import argparse
import sys

from .scanner import run_scan, SEVERITY_ORDER
from .reporter import print_terminal_report, save_json_report
from .models import ScanResult


def _apply_ignore_filters(
    result: ScanResult,
    ignore_severities: set[str],
    ignore_ids: set[str],
) -> ScanResult:
    """
    Return a new ScanResult with findings filtered out by severity or ID.
    The summary counts are recalculated to match the filtered set.
    """
    filtered = [
        f for f in result.findings
        if f.severity not in ignore_severities
        and f.pattern_id not in ignore_ids
    ]

    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in filtered:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    return ScanResult(
        repo_path=result.repo_path,
        scan_time=result.scan_time,
        files_scanned=result.files_scanned,
        files_skipped=result.files_skipped,
        total_findings=len(filtered),
        findings_by_severity=counts,
        findings=filtered,
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="repo_scanner",
        description="Scan a repository for data-exfiltration risks and suspicious network calls.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py /path/to/repo
  python main.py /path/to/repo --severity HIGH
  python main.py /path/to/repo --ignore-severity INFO
  python main.py /path/to/repo --ignore-severity INFO LOW
  python main.py /path/to/repo --ignore-id I001 I002
  python main.py /path/to/repo --ignore-severity INFO --ignore-id H003 --output report.json
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
        "--ignore-severity",
        nargs="+",
        metavar="SEVERITY",
        default=[],
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
        help="Suppress all findings of these severity levels. "
             "Example: --ignore-severity INFO LOW",
    )
    parser.add_argument(
        "--ignore-id",
        nargs="+",
        metavar="ID",
        default=[],
        help="Suppress findings with these specific rule IDs. "
             "Example: --ignore-id I001 I002 H003",
    )
    parser.add_argument(
        "--output",
        default=None,
        metavar="FILE",
        help="Optional path to save a JSON report.",
    )

    args = parser.parse_args()

    ignore_severities = {s.upper() for s in args.ignore_severity}
    ignore_ids = {i.upper() for i in args.ignore_id}

    # Build a human-readable summary of active ignores for the header
    ignore_notes = []
    if ignore_severities:
        ignore_notes.append(f"ignoring severities: {', '.join(sorted(ignore_severities))}")
    if ignore_ids:
        ignore_notes.append(f"ignoring IDs: {', '.join(sorted(ignore_ids))}")
    ignore_str = f"  ({';  '.join(ignore_notes)})" if ignore_notes else ""

    print(f"[*] Starting scan: {args.repo}  (min severity: {args.severity}){ignore_str}")

    result = run_scan(args.repo, min_severity=args.severity)

    if ignore_severities or ignore_ids:
        result = _apply_ignore_filters(result, ignore_severities, ignore_ids)

    print_terminal_report(result)

    if args.output:
        save_json_report(result, args.output)


if __name__ == "__main__":
    main()
