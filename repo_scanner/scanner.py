# scanner.py
"""
Core scanning logic.

walk_repo  — walks the filesystem, skipping dirs from skip_dirs.py
scan_file  — runs all patterns + entropy analysis against a single file
run_scan   — orchestrates a full repo scan and returns a ScanResult
"""

import os
import sys
from datetime import datetime
from pathlib import Path

from .config import (
    MAX_FILE_SIZE_BYTES,
    SKIP_HIDDEN_DIRS,
    BINARY_PROBE_BYTES,
    MATCH_DISPLAY_LENGTH,
    LINE_DISPLAY_LENGTH,
    ENTROPY_SEVERITY,
)
from .entropy import scan_entropy
from .models import Finding, ScanResult
from .patterns import PATTERNS
from .config import SKIP_DIRS, SKIP_FILE_EXTENSIONS

SEVERITY_ORDER: dict[str, int] = {
    "CRITICAL": 0,
    "HIGH":     1,
    "MEDIUM":   2,
    "LOW":      3,
    "INFO":     4,
}


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _is_likely_binary(path: Path) -> bool:
    """Probe the first BINARY_PROBE_BYTES bytes for null bytes."""
    try:
        chunk = path.read_bytes()[:BINARY_PROBE_BYTES]
        return b"\x00" in chunk
    except OSError:
        return True


def _should_scan(path: Path, skip_extensions: set[str] | None = None) -> bool:
    """
    Return True if the file should be scanned:
      - extension not in the combined skip set (SKIP_EXTENSIONS + CLI extras)
      - within MAX_FILE_SIZE_BYTES (0 = no limit)
      - not binary
    No extension allowlist — every text file is scanned.
    """
    combined_skip_exts = {e.lower() for e in SKIP_FILE_EXTENSIONS} | {e.lower() for e in (skip_extensions or set())}
    if path.suffix.lower() in combined_skip_exts:
        return False

    try:
        size = path.stat().st_size
    except OSError:
        return False

    if MAX_FILE_SIZE_BYTES > 0 and size > MAX_FILE_SIZE_BYTES:
        return False

    return not _is_likely_binary(path)


# ─────────────────────────────────────────────────────────────────────────────
# Walk
# ─────────────────────────────────────────────────────────────────────────────

def walk_repo(repo_path: Path, skip_extensions: set[str] | None = None):
    """
    Yield (file_path, should_skip: bool) for every file under repo_path.

    Directories are pruned when they appear in SKIP_DIRS, or (if
    SKIP_HIDDEN_DIRS is True) when their name starts with ".".
    """
    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [
            d for d in dirs
            if d not in SKIP_DIRS
            and not (SKIP_HIDDEN_DIRS and d.startswith("."))
        ]
        for fname in files:
            fpath = Path(root) / fname
            yield fpath, not _should_scan(fpath, skip_extensions)


# ─────────────────────────────────────────────────────────────────────────────
# File scanner
# ─────────────────────────────────────────────────────────────────────────────

def scan_file(
    file_path: Path,
    repo_root: Path,
    min_severity: str,
) -> list[Finding]:
    """Run all regex patterns + entropy analysis against a single file."""
    findings: list[Finding] = []
    min_level = SEVERITY_ORDER[min_severity]

    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
    except (PermissionError, OSError):
        return findings

    lines = content.splitlines()
    relative_path = str(file_path.relative_to(repo_root))

    # ── Regex pattern scan ────────────────────────────────────────────────────
    for pat_cfg in PATTERNS:
        if SEVERITY_ORDER[pat_cfg["severity"]] > min_level:
            continue

        pat = pat_cfg["pattern"]

        for line_no, line in enumerate(lines, start=1):
            for m in pat.finditer(line):
                findings.append(Finding(
                    pattern_id=pat_cfg["id"],
                    severity=pat_cfg["severity"],
                    category=pat_cfg["category"],
                    name=pat_cfg["name"],
                    description=pat_cfg["description"],
                    advice=pat_cfg["advice"],
                    file=relative_path,
                    line_number=line_no,
                    line_content=line.strip()[:LINE_DISPLAY_LENGTH],
                    match=m.group(0)[:MATCH_DISPLAY_LENGTH],
                ))

    # ── Entropy scan ──────────────────────────────────────────────────────────
    if SEVERITY_ORDER.get(ENTROPY_SEVERITY, 99) <= min_level:
        findings.extend(scan_entropy(file_path, repo_root))

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Orchestrator
# ─────────────────────────────────────────────────────────────────────────────

def run_scan(
    repo_path: str,
    min_severity: str = "INFO",
    skip_extensions: set[str] | None = None,
) -> ScanResult:
    """Walk *repo_path*, scan every eligible file, and return a ScanResult."""
    root = Path(repo_path).resolve()
    if not root.exists():
        print(f"[ERROR] Path does not exist: {root}", file=sys.stderr)
        sys.exit(1)

    all_findings: list[Finding] = []
    files_scanned = 0
    files_skipped = 0

    for fpath, skipped in walk_repo(root, skip_extensions):
        if skipped:
            files_skipped += 1
            continue
        files_scanned += 1
        all_findings.extend(scan_file(fpath, root, min_severity))

    # Sort: severity -> file path -> line number
    all_findings.sort(
        key=lambda f: (SEVERITY_ORDER.get(f.severity, 99), f.file, f.line_number)
    )

    counts: dict[str, int] = {s: 0 for s in SEVERITY_ORDER}
    for f in all_findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    return ScanResult(
        repo_path=str(root),
        scan_time=datetime.now().isoformat(),
        files_scanned=files_scanned,
        files_skipped=files_skipped,
        total_findings=len(all_findings),
        findings_by_severity=counts,
        findings=all_findings,
    )
