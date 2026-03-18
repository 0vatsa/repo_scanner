# models.py
"""Shared dataclasses used across the scanner."""

from dataclasses import dataclass, field


@dataclass
class Finding:
    pattern_id: str
    severity: str
    category: str
    name: str
    description: str
    advice: str
    file: str
    line_number: int
    line_content: str
    match: str


@dataclass
class ScanResult:
    repo_path: str
    scan_time: str
    files_scanned: int
    files_skipped: int
    total_findings: int
    findings_by_severity: dict
    findings: list = field(default_factory=list)
