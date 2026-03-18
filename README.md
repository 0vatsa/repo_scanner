# repo_scanner

Enterprise Data Exfiltration Risk Scanner — scans a codebase for URLs,
suspicious network calls, hardcoded secrets, and other exfiltration vectors.

## Usage

```bash
# scan everything, show all severities
python main.py /path/to/repo

# only show HIGH and CRITICAL findings
python main.py /path/to/repo --severity HIGH

# save a machine-readable JSON report as well
python main.py /path/to/repo --output report.json

# or invoke as a package directly
python -m repo_scanner /path/to/repo --severity MEDIUM
```

## Package layout

```
repo_scanner/
├── main.py                  ← top-level convenience shim
└── repo_scanner/
    ├── __init__.py          ← public API
    ├── __main__.py          ← CLI (python -m repo_scanner)
    ├── models.py            ← Finding / ScanResult dataclasses
    ├── patterns.py          ← all detection patterns (edit to add/remove rules)
    ├── scanner.py           ← walk + scan logic
    ├── reporter.py          ← terminal + JSON output
    └── skip_dirs.py         ← ✏️  user-editable directory skip list
```

## Customising

### Skip directories
Edit `repo_scanner/skip_dirs.py` — add any folder names you want ignored:

```python
SKIP_DIRS: set[str] = {
    ...
    "my_generated_code",
    "legacy_archive",
}
```

### Add / remove detection patterns
Edit `repo_scanner/patterns.py`. Each pattern is a plain dict:

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

## What it detects

| ID   | Severity | Description |
|------|----------|-------------|
| C001 | CRITICAL | Hardcoded API key / token |
| C002 | CRITICAL | AWS access key ID |
| C003 | CRITICAL | Private key PEM block |
| C004 | CRITICAL | DNS exfiltration encoding pattern |
| C005 | CRITICAL | Ngrok / tunnel URL (with or without scheme) |
| H001 | HIGH | HTTP URL (plain-text) |
| H002 | HIGH | HTTPS URL |
| H003 | HIGH | **Bare domain reference — no `https://` prefix** |
| H004 | HIGH | Shell command execution |
| H005 | HIGH | Raw socket creation |
| H006 | HIGH | Base64 encoding of payload |
| H007 | HIGH | Webhook / callback URL |
| H008 | HIGH | Cloud storage upload (S3/GCS/Azure) |
| H009 | HIGH | curl / wget with data upload flag |
| H010 | HIGH | Netcat / Socat reverse-shell invocation |
| M001 | MEDIUM | Third-party telemetry / analytics SDK |
| M002 | MEDIUM | LLM / AI API call |
| M003 | MEDIUM | Sensitive environment variable read |
| M004 | MEDIUM | File read near network call |
| M005 | MEDIUM | Hex / URL encoding of data |
| M006 | MEDIUM | FTP / SFTP transfer |
| M007 | MEDIUM | SMTP / email sending |
| M008 | MEDIUM | Insecure deserialisation (pickle / Java) |
| L001 | LOW | External IP address literal |
| L002 | LOW | Telemetry enabled flag |
| L003 | LOW | Sensitive variable name in log statement |
| L004 | LOW | TLS verification disabled |
| I001 | INFO | localhost / loopback reference |
| I002 | INFO | Security-related TODO / FIXME comment |

## File scanning policy

All files are scanned **except**:
- Directories listed in `skip_dirs.py`
- Hidden directories (names starting with `.`)
- Files larger than 2 MB
- Files that appear to be binary (contain null bytes in the first 8 KB)

There is no extension allowlist — every text file is scanned regardless of type.
