# repo_scanner/__init__.py
"""
repo_scanner — Enterprise Data Exfiltration Risk Scanner
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Public API:
    run_scan(repo_path, min_severity) -> ScanResult
    print_terminal_report(result)
    save_json_report(result, path)
"""

from .scanner import run_scan
from .reporter import print_terminal_report, save_json_report
from .models import Finding, ScanResult

__all__ = [
    "run_scan",
    "print_terminal_report",
    "save_json_report",
    "Finding",
    "ScanResult",
]
