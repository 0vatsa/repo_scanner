# entropy.py
"""
Shannon-entropy scanner.

Finds high-randomness strings that don't match any named pattern —
custom tokens, undocumented API keys, session secrets, etc.

Algorithm
─────────
For each line we extract every contiguous run of characters that belongs
to one of the configured charsets (base64, alphanumeric, hex).  Each run
is measured with Shannon entropy H = -Σ p_i * log2(p_i).  Runs that are:
  • within [ENTROPY_MIN_LENGTH, ENTROPY_MAX_LENGTH]
  • above ENTROPY_THRESHOLD bits/char
are emitted as findings.

False-positive reduction
─────────────────────────
• Very short strings are skipped (too little data → inflated entropy).
• Very long strings are skipped (tend to be blobs, not secrets).
• Runs that are pure repetition (e.g. "aaaa") score ~0 and are ignored.
• The threshold is configurable in config.py.
"""

import math
import re
from pathlib import Path

from .models import Finding
from .config import (
    ENTROPY_SCAN_ENABLED,
    ENTROPY_MIN_LENGTH,
    ENTROPY_MAX_LENGTH,
    ENTROPY_THRESHOLD,
    ENTROPY_CHARSETS,
    ENTROPY_SEVERITY,
    LINE_DISPLAY_LENGTH,
    MATCH_DISPLAY_LENGTH,
)


def _shannon_entropy(token: str) -> float:
    """Return Shannon entropy in bits per character for *token*."""
    if not token:
        return 0.0
    freq = {}
    for ch in token:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(token)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _extract_tokens(line: str, charset: str) -> list[str]:
    """Extract all maximal runs of characters from *charset* found in *line*."""
    pattern = f"[{re.escape(charset)}]+"
    return re.findall(pattern, line)


def scan_entropy(
    file_path: Path,
    repo_root: Path,
) -> list[Finding]:
    """
    Scan a single file for high-entropy strings.
    Returns an empty list if ENTROPY_SCAN_ENABLED is False.
    """
    if not ENTROPY_SCAN_ENABLED:
        return []

    findings: list[Finding] = []
    relative_path = str(file_path.relative_to(repo_root))

    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
    except (PermissionError, OSError):
        return findings

    lines = content.splitlines()

    for line_no, line in enumerate(lines, start=1):
        seen_tokens: set[str] = set()   # dedupe matches on the same line

        for charset in ENTROPY_CHARSETS:
            for token in _extract_tokens(line, charset):
                if token in seen_tokens:
                    continue
                if not (ENTROPY_MIN_LENGTH <= len(token) <= ENTROPY_MAX_LENGTH):
                    continue

                score = _shannon_entropy(token)
                if score < ENTROPY_THRESHOLD:
                    continue

                seen_tokens.add(token)
                findings.append(Finding(
                    pattern_id="E001",
                    severity=ENTROPY_SEVERITY,
                    category="Entropy / Secret",
                    name="High-Entropy String",
                    description=(
                        f"String with Shannon entropy {score:.2f} bits/char "
                        f"(threshold: {ENTROPY_THRESHOLD}) — likely a hardcoded secret "
                        "that does not match any named pattern."
                    ),
                    advice=(
                        "Inspect this string manually. If it is a secret, move it to an "
                        "environment variable or secrets manager."
                    ),
                    file=relative_path,
                    line_number=line_no,
                    line_content=line.strip()[:LINE_DISPLAY_LENGTH],
                    match=token[:MATCH_DISPLAY_LENGTH],
                ))

    return findings
