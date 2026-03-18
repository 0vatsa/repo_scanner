# config.py
# ─────────────────────────────────────────────────────────────────────────────
# User-editable runtime parameters for repo_scanner.
#
# Every value is validated by an assert at the bottom of this file.
# If you set an invalid value you'll get a clear AssertionError at startup
# rather than a silent misbehaviour later.
# ─────────────────────────────────────────────────────────────────────────────


# ── File traversal ────────────────────────────────────────────────────────────

# Directories the scanner will never descend into.
# Matching is by directory *name only* (not full path), so "build" skips every
# directory named "build" anywhere in the tree.
# Hidden directories (names starting with ".") are skipped separately via
# SKIP_HIDDEN_DIRS below, but you can also list them here explicitly.
SKIP_DIRS: set[str] = {
    # ── Version control ──────────────────────────────────────────────────────
    ".git",
    ".svn",
    ".hg",

    # ── Dependency caches ─────────────────────────────────────────────────────
    "node_modules",
    "vendor",           # Go, PHP Composer, Ruby bundler
    "third_party",

    # ── Python artefacts ─────────────────────────────────────────────────────
    "__pycache__",
    ".pytest_cache",
    ".tox",
    ".eggs",
    "venv",
    ".venv",
    "env",
    ".env",             # virtualenv named ".env"

    # ── Build outputs ─────────────────────────────────────────────────────────
    "dist",
    "build",
    "target",           # Maven / Rust / Scala
    "out",

    # ── IDE metadata ──────────────────────────────────────────────────────────
    ".idea",
    ".vscode",

    # ── ADD YOUR OWN ENTRIES BELOW ────────────────────────────────────────────
    # "my_internal_cache",
    # "generated_proto",
}

# Maximum size (in bytes) a file may be before it is skipped entirely.
# Default: 2 MB.  Set to 0 to disable the limit (not recommended on large repos).
MAX_FILE_SIZE_BYTES: int = 2 * 1024 * 1024   # 2 MB

# When True, directories whose names begin with "." are skipped automatically
# (e.g. .git, .github, .vscode).
# Set to False only if you intentionally want to scan hidden directories
# (they will still be subject to SKIP_DIRS in skip_dirs.py).
SKIP_HIDDEN_DIRS: bool = True

# Number of bytes read from the start of each file to determine whether it
# is binary (null-byte probe). Increase for more accuracy, decrease for speed.
BINARY_PROBE_BYTES: int = 8192   # 8 KB


# File extensions to skip entirely (case-insensitive, leading dot required).
# Default: empty — all text files are scanned.
# Add extensions directly to this set:
#
#   SKIP_FILE_EXTENSIONS: set[str] = {".md", ".txt", ".lock"}
#
SKIP_FILE_EXTENSIONS: set[str] = set()


# ── Entropy analysis ─────────────────────────────────────────────────────────

# Enable Shannon-entropy scanning for high-randomness strings.
# Catches secrets that don't match any known pattern (custom tokens, UUIDs
# used as secrets, undocumented API keys, etc.).
ENTROPY_SCAN_ENABLED: bool = True

# Strings shorter than this are ignored by the entropy scanner —
# short random strings produce too many false positives.
ENTROPY_MIN_LENGTH: int = 20

# Strings longer than this are ignored — very long strings are usually
# base64-encoded blobs or hashes, not secrets in the traditional sense.
# Set to a higher value if you want to catch those too.
ENTROPY_MAX_LENGTH: int = 120

# Shannon entropy threshold (bits per character, 0.0 – 4.0 for base64-charset).
# A completely random base64 string scores ≈ 4.0.
# Typical passwords/tokens score between 3.5 – 4.0.
# English prose scores around 2.0.
# Recommended range: 3.5 – 3.8. Lower = more findings, more noise.
ENTROPY_THRESHOLD: float = 3.5

# Character sets considered when measuring entropy.
# Each set is tested independently; a match on *any* set triggers a finding.
# Remove a set to reduce false positives for that alphabet.
ENTROPY_CHARSETS: list[str] = [
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/=",  # base64
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",     # alphanumeric
    "0123456789abcdefABCDEF",                                                # hex
]

# Severity assigned to entropy findings.
# Change to "MEDIUM" if you find CRITICAL too noisy for your repo.
ENTROPY_SEVERITY: str = "CRITICAL"


# ── Report / output ───────────────────────────────────────────────────────────

# Maximum length (characters) of a matched string shown in terminal output.
# Does not affect JSON output.
MATCH_DISPLAY_LENGTH: int = 120

# Maximum length (characters) of the source line shown in terminal output.
LINE_DISPLAY_LENGTH: int = 200


# ─────────────────────────────────────────────────────────────────────────────
# Validation — do not edit below this line
# ─────────────────────────────────────────────────────────────────────────────

assert isinstance(SKIP_DIRS, set),     "SKIP_DIRS must be a set"
assert all(isinstance(d, str) and len(d) > 0 for d in SKIP_DIRS),     "Every entry in SKIP_DIRS must be a non-empty string"

assert isinstance(MAX_FILE_SIZE_BYTES, int), \
    "MAX_FILE_SIZE_BYTES must be an int"
assert MAX_FILE_SIZE_BYTES >= 0, \
    "MAX_FILE_SIZE_BYTES must be >= 0 (use 0 to disable the size limit)"

assert isinstance(SKIP_HIDDEN_DIRS, bool), \
    "SKIP_HIDDEN_DIRS must be a bool (True or False)"

assert isinstance(BINARY_PROBE_BYTES, int) and BINARY_PROBE_BYTES > 0, \
    "BINARY_PROBE_BYTES must be a positive int"

assert isinstance(ENTROPY_SCAN_ENABLED, bool), \
    "ENTROPY_SCAN_ENABLED must be a bool (True or False)"

assert isinstance(ENTROPY_MIN_LENGTH, int) and ENTROPY_MIN_LENGTH > 0, \
    "ENTROPY_MIN_LENGTH must be a positive int"

assert isinstance(ENTROPY_MAX_LENGTH, int) and ENTROPY_MAX_LENGTH > 0, \
    "ENTROPY_MAX_LENGTH must be a positive int"

assert ENTROPY_MIN_LENGTH < ENTROPY_MAX_LENGTH, \
    "ENTROPY_MIN_LENGTH must be strictly less than ENTROPY_MAX_LENGTH"

assert isinstance(ENTROPY_THRESHOLD, (int, float)) and 0.0 < ENTROPY_THRESHOLD <= 4.0, \
    "ENTROPY_THRESHOLD must be a float in the range (0.0, 4.0]"

assert isinstance(ENTROPY_CHARSETS, list) and len(ENTROPY_CHARSETS) > 0, \
    "ENTROPY_CHARSETS must be a non-empty list of strings"
assert all(isinstance(s, str) and len(s) > 0 for s in ENTROPY_CHARSETS), \
    "Every entry in ENTROPY_CHARSETS must be a non-empty string"

assert ENTROPY_SEVERITY in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}, \
    "ENTROPY_SEVERITY must be one of: CRITICAL, HIGH, MEDIUM, LOW, INFO"

assert isinstance(SKIP_FILE_EXTENSIONS, set), \
    "SKIP_FILE_EXTENSIONS must be a set"
assert all(isinstance(e, str) and e.startswith(".") for e in SKIP_FILE_EXTENSIONS), \
    "Every entry in SKIP_FILE_EXTENSIONS must be a string starting with '.' (e.g. '.md')"

assert isinstance(MATCH_DISPLAY_LENGTH, int) and MATCH_DISPLAY_LENGTH > 0, \
    "MATCH_DISPLAY_LENGTH must be a positive int"

assert isinstance(LINE_DISPLAY_LENGTH, int) and LINE_DISPLAY_LENGTH > 0, \
    "LINE_DISPLAY_LENGTH must be a positive int"