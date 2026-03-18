# repo_scanner

**Enterprise Data Exfiltration Risk Scanner** — scans a codebase for URLs,
suspicious network calls, hardcoded secrets, high-entropy strings, and other
vectors an open-source dependency (or a malicious contributor) could use to
phone home with your data.

---

## Quick start

```bash
# show all findings
python3 main.py /path/to/repo

# only show HIGH and CRITICAL
python3 main.py /path/to/repo --severity HIGH

# suppress an entire severity level
python3 main.py /path/to/repo --ignore-severity INFO

# suppress multiple severities
python3 main.py /path/to/repo --ignore-severity INFO LOW

# suppress specific rule IDs
python3 main.py /path/to/repo --ignore-id I001 I002

# mix and match — typical real-world usage
python3 main.py /path/to/repo --ignore-severity INFO --ignore-id H003 E001

# save a JSON report
python3 main.py /path/to/repo --output report.json

# save a CSV report (opens in Excel / Google Sheets / LibreOffice Calc / Text Editor)
python3 main.py /path/to/repo --output-csv report.csv

# save both at once
python3 main.py /path/to/repo --output report.json --output-csv report.csv

# skip specific file extensions
python3 main.py /path/to/repo --skip-ext .md .txt .lock

# leading dot is optional
python3 main.py /path/to/repo --skip-ext md txt lock

# everything combined
python3 main.py /path/to/repo --severity HIGH --ignore-id C004 --output report.json --output-csv report.csv
```

> **Note:** always run from the project root (the folder containing `main.py`), or use the full path: `python3 /full/path/to/repo_scanner/main.py /path/to/scan`

---

## How this scanner is different

Most existing tools (Gitleaks, TruffleHog, Bandit, Semgrep) answer the question:
**"Does this code contain a known secret?"**

This scanner answers a different question:
**"Could this code be calling home with your enterprise data?"**

The focus is on *network sinks and exfiltration vectors*, not just credential
patterns. Unique detections include:

- **Bare domain references without a scheme** — `example.com` used directly in
  code (no `https://` prefix) is invisible to URL-only scanners but fully
  functional as a network destination.
- **Tunnel / ngrok URLs** — commonly used to exfiltrate data through firewalls,
  with or without the `https://` prefix.
- **Shannon entropy analysis** — catches custom tokens, session secrets, and
  undocumented API keys that don't match any named pattern.
- **Outbound network sinks** — raw sockets, DNS exfiltration encoding, curl/wget
  data-upload invocations, FTP/SFTP, SMTP, cloud storage uploads.
- **Telemetry SDK detection** — flags analytics and error-reporting libraries
  that silently send runtime data to third parties.

### Comparison with similar tools

| Capability | Gitleaks | TruffleHog | Bandit | Semgrep | **repo_scanner** |
|---|:---:|:---:|:---:|:---:|:---:|
| Secrets / hardcoded credentials | ✅ | ✅ | ✅ | ✅ | ✅ |
| HTTP/HTTPS URL detection | ❌ | ❌ | ❌ | partial | ✅ |
| Bare domain (no scheme) detection | ❌ | ❌ | ❌ | ❌ | ✅ |
| Exfiltration patterns (sockets, curl, DNS) | ❌ | ❌ | partial | partial | ✅ |
| Telemetry SDK detection | ❌ | ❌ | ❌ | ❌ | ✅ |
| Shannon entropy analysis | partial | ✅ | ❌ | ❌ | ✅ |
| Credential *verification* (live check) | ❌ | ✅ | ❌ | ❌ | ❌ |
| Git history scanning | ✅ | ✅ | ❌ | ❌ | ❌ |
| Multi-language deep SAST | ❌ | ❌ | Python only | ✅ | regex-based |
| Zero dependencies (stdlib only) | ✅ | ❌ | ❌ | ❌ | ✅ |
| Enterprise exfiltration focus | ❌ | ❌ | ❌ | ❌ | ✅ |

**Recommended pipeline** — these tools are complementary, not mutually exclusive:

```
Gitleaks        →  pre-commit hook, fast secret blocking
TruffleHog      →  CI/CD, live credential verification
Bandit/Semgrep  →  CI/CD, general SAST
repo_scanner    →  CI/CD, network exfiltration & calling-home focus
```

---

## Package layout

```
repo_scanner/
├── main.py                      ← convenience entry point
└── repo_scanner/
    ├── __init__.py              ← public API
    ├── __main__.py              ← python -m repo_scanner
    ├── models.py                ← Finding / ScanResult dataclasses
    ├── patterns.py              ← all regex detection rules
    ├── entropy.py               ← Shannon entropy analysis
    ├── scanner.py               ← walk + scan engine
    ├── reporter.py              ← terminal + JSON output
    └── config.py                ← ✏️  all runtime parameters, skip lists, and entropy tuning
```

---

## CLI reference

```
python3 main.py <repo> [options]
```

| Argument | Description |
|---|---|
| `repo` | Path to the repository or folder to scan |
| `--severity LEVEL` | Minimum severity to include: `CRITICAL` `HIGH` `MEDIUM` `LOW` `INFO` (default: `INFO`) |
| `--ignore-severity LEVEL [LEVEL ...]` | Suppress all findings of these severity levels |
| `--ignore-id ID [ID ...]` | Suppress findings with these specific rule IDs |
| `--output FILE` | Save a JSON report to this path |
| `--output-csv FILE` | Save a CSV report to this path (compatible with Excel / Google Sheets) |
| `--skip-ext EXT [EXT ...]` | Skip files with these extensions. Leading dot optional. Example: `--skip-ext .md .txt .lock` |

### `--severity` vs `--ignore-severity`

These two flags work at different ends of the filter:

- `--severity HIGH` — only runs patterns at HIGH and above; INFO/MEDIUM/LOW patterns are never evaluated
- `--ignore-severity INFO` — runs everything, then drops INFO findings from the output

Use `--severity` when you want a fast, noise-free scan. Use `--ignore-severity` when you want the full scan but need to suppress specific noise categories after the fact.

### CSV columns

The CSV report contains one row per finding with these columns:

| Column | Description |
|---|---|
| `severity` | CRITICAL / HIGH / MEDIUM / LOW / INFO |
| `pattern_id` | Rule ID (e.g. `H002`, `E001`) |
| `category` | Grouping (e.g. Outbound HTTP, Hardcoded Secret) |
| `name` | Short rule name |
| `file` | Relative path to the file |
| `line_number` | Line number of the finding |
| `match` | The exact string that matched |
| `line_content` | Full source line (truncated at 200 chars) |
| `description` | Why this pattern is suspicious |
| `advice` | Recommended remediation |

---

## Configuration

### `repo_scanner/config.py` — all configuration

All tuneable parameters, skip lists, and thresholds live in one place.
Every value is validated by an `assert` at import time, so a misconfiguration
fails loudly at startup.

To skip directories, edit `SKIP_DIRS` directly in the set:

```python
SKIP_DIRS: set[str] = {
    "node_modules",
    "vendor",
    # add your own:
    "my_generated_code",
    "legacy_archive",
}
```

To skip file extensions, edit `SKIP_FILE_EXTENSIONS`:

```python
SKIP_FILE_EXTENSIONS: set[str] = {".md", ".txt", ".lock"}
```

| Parameter | Default | Description |
|---|---|---|
| `MAX_FILE_SIZE_BYTES` | `2097152` (2 MB) | Skip files larger than this. Set to `0` to disable. |
| `SKIP_HIDDEN_DIRS` | `True` | Skip directories whose names start with `.` |
| `BINARY_PROBE_BYTES` | `8192` (8 KB) | Bytes read to detect binary files |
| `SKIP_DIRS` | see config.py | Directory names to never descend into |
| `SKIP_FILE_EXTENSIONS` | `set()` (empty) | File extensions to skip entirely. Example: `{".md", ".txt", ".lock"}` |
| `ENTROPY_SCAN_ENABLED` | `True` | Toggle entropy scanning on/off |
| `ENTROPY_MIN_LENGTH` | `20` | Minimum token length for entropy analysis |
| `ENTROPY_MAX_LENGTH` | `120` | Maximum token length for entropy analysis |
| `ENTROPY_THRESHOLD` | `3.5` | Shannon entropy threshold (bits/char). Higher = fewer findings. |
| `ENTROPY_CHARSETS` | base64, alphanumeric, hex | Character sets tested by the entropy scanner |
| `ENTROPY_SEVERITY` | `CRITICAL` | Severity assigned to entropy findings |
| `MATCH_DISPLAY_LENGTH` | `120` | Max chars of a match shown in terminal output |
| `LINE_DISPLAY_LENGTH` | `200` | Max chars of a source line shown in terminal output |

### Adding / removing detection patterns

Edit `repo_scanner/patterns.py`. Each rule is a plain dict:

```python
{
    "id": "H011",
    "severity": "HIGH",
    "category": "Outbound HTTP",
    "name": "My Custom Rule",
    "description": "Why this is suspicious.",
    "pattern": re.compile(r'my_regex_here'),
    "advice": "What the developer should do.",
},
```

---

## Detection rules

### Regex patterns

| ID   | Severity | Category | Description |
|------|----------|----------|-------------|
| C001 | CRITICAL | Hardcoded Secret | API key / token hardcoded in source |
| C002 | CRITICAL | Hardcoded Secret | AWS access key ID |
| C003 | CRITICAL | Hardcoded Secret | Private key PEM block |
| C004 | CRITICAL | Data Exfiltration | DNS exfiltration encoding pattern |
| C005 | CRITICAL | Data Exfiltration | Ngrok / tunnel URL (with or without scheme) |
| H001 | HIGH | Outbound HTTP | Plain `http://` URL |
| H002 | HIGH | Outbound HTTP | `https://` URL |
| H003 | HIGH | Outbound HTTP | **Bare domain — no scheme** (e.g. `api.evil.io`) |
| H004 | HIGH | Shell Execution | `subprocess`, `os.system`, `eval`, `shell=True` |
| H005 | HIGH | Network Socket | Raw socket creation |
| H006 | HIGH | Encoding | Base64 encoding of a payload |
| H007 | HIGH | Webhook | Webhook / callback URL assignment |
| H008 | HIGH | Cloud Storage | S3 / GCS / Azure Blob upload |
| H009 | HIGH | Data Exfiltration | `curl` / `wget` with data-upload flag |
| H010 | HIGH | Data Exfiltration | Netcat / Socat reverse-shell invocation |
| M001 | MEDIUM | Telemetry | Third-party analytics / telemetry SDK |
| M002 | MEDIUM | AI / LLM | External LLM API call (OpenAI, Anthropic, etc.) |
| M003 | MEDIUM | Config | Sensitive environment variable read |
| M004 | MEDIUM | File System | File read in proximity to a network call |
| M005 | MEDIUM | Encoding | Hex / URL encoding of data |
| M006 | MEDIUM | Network | FTP / SFTP transfer |
| M007 | MEDIUM | Network | SMTP / email sending |
| M008 | MEDIUM | Serialisation | Insecure deserialisation (pickle / Java) |
| L001 | LOW | Network | External public IP address literal |
| L002 | LOW | Telemetry | Telemetry enabled flag set to true |
| L003 | LOW | Logging | Sensitive variable name in a log statement |
| L004 | LOW | Network | TLS/SSL verification disabled |
| I001 | INFO | Network | localhost / loopback reference |
| I002 | INFO | Comment | Security-related TODO / FIXME |

### Entropy analysis

| ID   | Severity (default) | Description |
|------|--------------------|-------------|
| E001 | CRITICAL | High-entropy string (≥ 3.5 bits/char) not matched by any named pattern |

Entropy severity and threshold are tunable in `config.py`.

---

## File scanning policy

Every file is scanned **except**:

- Directories in `skip_dirs.py`
- Hidden directories (names starting with `.`) — controlled by `SKIP_HIDDEN_DIRS` in `config.py`
- Files larger than `MAX_FILE_SIZE_BYTES` (default 2 MB, `0` = no limit)
- Files containing null bytes in their first `BINARY_PROBE_BYTES` (detected as binary)

There is no extension allowlist — every text file is scanned regardless of type.