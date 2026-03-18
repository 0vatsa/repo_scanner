# skip_dirs.py
# ─────────────────────────────────────────────────────────────────────────────
# Directories that the scanner will NEVER descend into.
#
# Edit this file freely:
#   • Add any internal cache/build folder names you want ignored.
#   • Matching is by directory *name only* (not full path), so "build" will
#     skip every directory literally named "build" anywhere in the tree.
#   • Hidden directories (names starting with ".") are always skipped
#     automatically, so you don't need to list them here unless you want to
#     be explicit.
# ─────────────────────────────────────────────────────────────────────────────

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

    # ─────────────────────────────────────────────────────────────────────────
    # ADD YOUR OWN ENTRIES BELOW THIS LINE
    # Example:
    #   "my_internal_cache",
    #   "generated_proto",
    # ─────────────────────────────────────────────────────────────────────────
}
