# scanner.py
"""
Core scanning logic.

walk_repo  — walks the filesystem, skipping dirs listed in skip_dirs.py
scan_file  — runs all patterns against a single file
run_scan   — orchestrates a full repo scan and returns a ScanResult
"""

import os
import sys
from datetime import datetime
from pathlib import Path

from .models import Finding, ScanResult
from .patterns import PATTERNS
from .skip_dirs import SKIP_DIRS

# Maximum file size to attempt reading (skip probable binary blobs)
MAX_FILE_SIZE: int = 2 * 1024 * 1024  # 2 MB

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
    """Quick heuristic: read the first 8 KB and check for null bytes."""
    try:
        chunk = path.read_bytes()[:8192]
        return b"\x00" in chunk
    except OSError:
        return True


def _should_scan(path: Path) -> bool:
    """
    Scan every file that:
      • is within the size limit
      • does not appear to be binary
    No extension allowlist — we scan everything.
    """
    try:
        if path.stat().st_size > MAX_FILE_SIZE:
            return False
    except OSError:
        return False
    return not _is_likely_binary(path)


# ─────────────────────────────────────────────────────────────────────────────
# Walk
# ─────────────────────────────────────────────────────────────────────────────

def walk_repo(repo_path: Path):
    """
    Yield (file_path, should_skip: bool) for every file under repo_path.

    Directories in SKIP_DIRS (or starting with '.') are pruned entirely.
    """
    for root, dirs, files in os.walk(repo_path):
        # Prune in-place so os.walk doesn't descend into skipped dirs
        dirs[:] = [
            d for d in dirs
            if d not in SKIP_DIRS and not d.startswith(".")
        ]
        for fname in files:
            fpath = Path(root) / fname
            yield fpath, not _should_scan(fpath)


# ─────────────────────────────────────────────────────────────────────────────
# File scanner
# ─────────────────────────────────────────────────────────────────────────────

def scan_file(
    file_path: Path,
    repo_root: Path,
    min_severity: str,
) -> list[Finding]:
    """Run all patterns against a single file and return a list of Findings."""
    findings: list[Finding] = []
    min_level = SEVERITY_ORDER[min_severity]

    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
    except (PermissionError, OSError):
        return findings

    lines = content.splitlines()
    relative_path = str(file_path.relative_to(repo_root))

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
                    line_content=line.strip()[:200],
                    match=m.group(0)[:120],
                ))

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Orchestrator
# ─────────────────────────────────────────────────────────────────────────────

def run_scan(repo_path: str, min_severity: str = "INFO") -> ScanResult:
    """Walk *repo_path*, scan every eligible file, and return a ScanResult."""
    root = Path(repo_path).resolve()
    if not root.exists():
        print(f"[ERROR] Path does not exist: {root}", file=sys.stderr)
        sys.exit(1)

    all_findings: list[Finding] = []
    files_scanned = 0
    files_skipped = 0

    for fpath, skipped in walk_repo(root):
        if skipped:
            files_skipped += 1
            continue
        files_scanned += 1
        all_findings.extend(scan_file(fpath, root, min_severity))

    # Sort: severity first, then file path, then line number
    all_findings.sort(
        key=lambda f: (SEVERITY_ORDER[f.severity], f.file, f.line_number)
    )

    counts: dict[str, int] = {s: 0 for s in SEVERITY_ORDER}
    for f in all_findings:
        counts[f.severity] += 1

    return ScanResult(
        repo_path=str(root),
        scan_time=datetime.now().isoformat(),
        files_scanned=files_scanned,
        files_skipped=files_skipped,
        total_findings=len(all_findings),
        findings_by_severity=counts,
        findings=all_findings,
    )
