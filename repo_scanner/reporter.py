# reporter.py
"""
Output formatters.

print_terminal_report  — coloured, human-readable console output
save_json_report       — machine-readable JSON dump
"""

import csv
import json
from dataclasses import asdict

from .models import ScanResult
from .scanner import SEVERITY_ORDER

# ── ANSI helpers ──────────────────────────────────────────────────────────────
SEVERITY_COLORS = {
    "CRITICAL": "\033[91m",   # bright red
    "HIGH":     "\033[31m",   # red
    "MEDIUM":   "\033[33m",   # yellow
    "LOW":      "\033[36m",   # cyan
    "INFO":     "\033[37m",   # white
}
RESET = "\033[0m"
BOLD  = "\033[1m"
DIM   = "\033[2m"


def _col(severity: str, text: str) -> str:
    return f"{SEVERITY_COLORS.get(severity, '')}{text}{RESET}"


# ── Terminal report ───────────────────────────────────────────────────────────

def print_terminal_report(result: ScanResult) -> None:
    print()
    print(f"{BOLD}{'═' * 70}{RESET}")
    print(f"{BOLD}  REPO EXFILTRATION RISK SCANNER — REPORT{RESET}")
    print(f"{BOLD}{'═' * 70}{RESET}")
    print(f"  Repo   : {result.repo_path}")
    print(f"  Time   : {result.scan_time}")
    print(f"  Scanned: {result.files_scanned} files  |  Skipped: {result.files_skipped}")
    print()

    print(f"  {BOLD}Findings Summary:{RESET}")
    for sev in SEVERITY_ORDER:
        count = result.findings_by_severity.get(sev, 0)
        bar = "█" * min(count, 40)
        print(f"  {_col(sev, f'{sev:<10}')} {count:>4}  {DIM}{bar}{RESET}")
    print()

    if not result.findings:
        print(f"  {BOLD}✅  No findings. Clean scan.{RESET}\n")
        return

    current_severity = None
    for f in result.findings:
        if f.severity != current_severity:
            current_severity = f.severity
            print(f"{BOLD}{'─' * 70}{RESET}")
            print(f"{BOLD}  {_col(f.severity, f.severity)} FINDINGS{RESET}")
            print(f"{BOLD}{'─' * 70}{RESET}")

        print(f"  [{f.pattern_id}] {BOLD}{f.name}{RESET}")
        print(f"  {DIM}File   :{RESET} {f.file}:{f.line_number}")
        print(f"  {DIM}Match  :{RESET} {_col(f.severity, f.match)}")
        print(f"  {DIM}Line   :{RESET} {f.line_content}")
        print(f"  {DIM}Advice :{RESET} {f.advice}")
        print()

    print(f"{BOLD}{'═' * 70}{RESET}")
    print(f"  Total: {result.total_findings} findings across {result.files_scanned} files.")
    print(f"{BOLD}{'═' * 70}{RESET}\n")


# ── JSON report ───────────────────────────────────────────────────────────────

def save_json_report(result: ScanResult, output_path: str) -> None:
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(asdict(result), fh, indent=2)
    print(f"[+] JSON report saved: {output_path}")


# ── CSV report ────────────────────────────────────────────────────────────────

try:
    import pandas as pd
    _PANDAS_AVAILABLE = True
except ImportError:
    _PANDAS_AVAILABLE = False

CSV_FIELDS = [
    "severity",
    "pattern_id",
    "category",
    "name",
    "file",
    "line_number",
    "match",
    "line_content",
    "description",
    "advice",
]

def _findings_to_rows(result: ScanResult) -> list[dict]:
    return [
        {
            "severity":     f.severity,
            "pattern_id":   f.pattern_id,
            "category":     f.category,
            "name":         f.name,
            "file":         f.file,
            "line_number":  f.line_number,
            "match":        f.match,
            "line_content": f.line_content,
            "description":  f.description,
            "advice":       f.advice,
        }
        for f in result.findings
    ]


def save_csv_report(result: ScanResult, output_path: str) -> None:
    rows = _findings_to_rows(result)

    if _PANDAS_AVAILABLE:
        pd.DataFrame(rows, columns=CSV_FIELDS).to_csv(
            output_path, index=False, encoding="utf-8"
        )
        print(f"[+] CSV report saved (pandas): {output_path}")
    else:
        with open(output_path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=CSV_FIELDS, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(rows)
        print(f"[+] CSV report saved (csv): {output_path}")