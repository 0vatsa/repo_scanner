# patterns.py
"""
All detection patterns, organised by severity: CRITICAL / HIGH / MEDIUM / LOW / INFO.

Each entry is a plain dict so patterns can be added, removed, or tweaked
without touching any other module.

Keys
────
id          : unique short code  (C001, H002, …)
severity    : CRITICAL | HIGH | MEDIUM | LOW | INFO
category    : human-readable grouping
name        : short display name
description : one-sentence explanation of the risk
pattern     : compiled re.Pattern
advice      : remediation hint shown in the report
"""

import re

PATTERNS: list[dict] = [

    # ══════════════════════════════════════════════════════════════════════════
    # CRITICAL
    # ══════════════════════════════════════════════════════════════════════════

    {
        "id": "C001",
        "severity": "CRITICAL",
        "category": "Hardcoded Secret",
        "name": "Hardcoded API Key / Token",
        "description": (
            "Hardcoded credential that may be used to authenticate outbound requests."
        ),
        "pattern": re.compile(
            r'(?i)(api[_\-]?key|api[_\-]?secret|auth[_\-]?token|access[_\-]?token'
            r'|secret[_\-]?key|client[_\-]?secret|private[_\-]?key)'
            r'\s*[=:]\s*["\']([A-Za-z0-9+/=_\-\.]{16,})["\']'
        ),
        "advice": (
            "Move secrets to environment variables or a secrets manager "
            "(e.g. Vault, AWS Secrets Manager)."
        ),
    },
    {
        "id": "C002",
        "severity": "CRITICAL",
        "category": "Hardcoded Secret",
        "name": "AWS Access Key ID",
        "description": "AWS access key embedded in source — can be used to exfiltrate data to AWS.",
        "pattern": re.compile(r'(?<![A-Z0-9])AKIA[0-9A-Z]{16}(?![A-Z0-9])'),
        "advice": "Rotate the key immediately and use IAM roles / environment variables.",
    },
    {
        "id": "C003",
        "severity": "CRITICAL",
        "category": "Hardcoded Secret",
        "name": "Private Key PEM Block",
        "description": "RSA/EC private key material hardcoded in source.",
        "pattern": re.compile(r'-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----'),
        "advice": "Remove private keys from source immediately. Store in a secure vault.",
    },
    {
        "id": "C004",
        "severity": "CRITICAL",
        "category": "Data Exfiltration",
        "name": "DNS Exfiltration Pattern",
        "description": (
            "Dynamic DNS lookups that encode data in subdomains — "
            "classic C2/exfiltration channel."
        ),
        "pattern": re.compile(
            r'(?i)(gethostbyname|dns\.resolve|nslookup|dig\s).*\+.*(\$|%|encode|base64|hex)'
        ),
        "advice": "Audit DNS calls; block dynamic subdomain construction at the network layer.",
    },
    {
        "id": "C005",
        "severity": "CRITICAL",
        "category": "Data Exfiltration",
        "name": "Ngrok / Tunnel URL",
        "description": (
            "Ngrok or similar tunnelling service URL — commonly used to "
            "exfiltrate data bypassing firewalls."
        ),
        "pattern": re.compile(
            r'(?i)(https?://)?[a-z0-9\-]+\.'
            r'(ngrok\.io|ngrok-free\.app|trycloudflare\.com'
            r'|serveo\.net|localhost\.run|telebit\.io|pagekite\.me)'
        ),
        "advice": "Block tunnel domains at the network/DNS layer. Remove from code.",
    },

    # ══════════════════════════════════════════════════════════════════════════
    # HIGH
    # ══════════════════════════════════════════════════════════════════════════

    {
        "id": "H001",
        "severity": "HIGH",
        "category": "Outbound HTTP",
        "name": "HTTP URL (plain-text)",
        "description": (
            "Plain HTTP URL — data in transit is unencrypted and can be intercepted."
        ),
        "pattern": re.compile(
            r'\bhttp://[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}(/[^\s"\'<>]*)?'
        ),
        "advice": "Upgrade to HTTPS. Audit the destination domain.",
    },
    {
        "id": "H002",
        "severity": "HIGH",
        "category": "Outbound HTTP",
        "name": "HTTPS URL",
        "description": (
            "HTTPS URL — review destination; could be an unauthorised exfiltration endpoint."
        ),
        "pattern": re.compile(
            r'\bhttps://[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}(/[^\s"\'<>]*)?'
        ),
        "advice": "Verify the domain is on an approved allowlist.",
    },
    {
        "id": "H003",
        "severity": "HIGH",
        "category": "Outbound HTTP",
        "name": "Bare Domain Reference (no scheme)",
        "description": (
            "Domain-like string without an http/https prefix — can still be used as a "
            "network destination in code (e.g. passed directly to a socket, HTTP client, "
            "or requests.get()). Often missed by URL-only scanners."
        ),
        # Matches things like:  "evil.io", 'data.example.com', api.attacker.net
        # Excludes:  localhost, common local suffixes, version strings (1.2.3.4),
        #            and lines that already contain http(s):// (covered by H001/H002).
        "pattern": re.compile(
            r'(?i)'
            r'(?<![/\w])'                               # not preceded by / or word char
            r'(?!https?://)'                            # not already a full URL
            r'(?!localhost\b)'
            r'(?!\d{1,3}(?:\.\d{1,3}){3})'             # not a bare IP (caught by L001)
            r'([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?'
            r'(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*'
            r'\.(com|io|net|org|co|dev|app|ai|cloud|xyz|info|biz|tech|online|site|me'
            r'|ru|cn|tk|top|club|store|live|pro|cc|tv|pw|ws|link|click|download'
            r'|sh|to|ly|gl|gg|run|pub|us|uk|de|fr|jp|br|in|au))'
            r'(?![a-zA-Z0-9\-])'                        # must end the token
        ),
        "advice": (
            "Verify this domain is an approved endpoint. Even without https://, "
            "it can be used as a network destination."
        ),
    },
    {
        "id": "H004",
        "severity": "HIGH",
        "category": "Shell / OS Execution",
        "name": "Shell Command Execution",
        "description": (
            "Dynamic shell execution — can be used to run curl/wget/nc to exfiltrate data."
        ),
        "pattern": re.compile(
            r'(?i)(subprocess\.(?:run|Popen|call|check_output)|os\.system|exec\(|eval\('
            r'|shell=True|Runtime\.getRuntime\(\)\.exec|ProcessBuilder'
            r'|cmd\.exe|/bin/sh|/bin/bash)'
        ),
        "advice": "Avoid shell=True. Prefer explicit argument lists. Audit all exec/eval calls.",
    },
    {
        "id": "H005",
        "severity": "HIGH",
        "category": "Network Socket",
        "name": "Raw Socket Creation",
        "description": (
            "Raw socket — bypasses HTTP-layer monitoring; data can be exfiltrated "
            "on arbitrary ports."
        ),
        "pattern": re.compile(
            r'(?i)(socket\.socket|new\s+Socket|net\.Dial|net\.connect|socket\.connect'
            r'|ServerSocket|DatagramSocket|zmq\.Context)'
        ),
        "advice": "Audit all raw socket usage. Enforce egress firewall rules.",
    },
    {
        "id": "H006",
        "severity": "HIGH",
        "category": "Encoding / Obfuscation",
        "name": "Base64 Encoded Payload",
        "description": (
            "Base64 encoding in a non-test context — common obfuscation layer "
            "for exfiltrated data."
        ),
        "pattern": re.compile(
            r'(?i)(base64\.b64encode|base64\.encode|btoa\('
            r'|Buffer\.from\([^)]+,\s*["\']base64["\']\)'
            r'|java\.util\.Base64)'
        ),
        "advice": "Verify that encoding is not applied to sensitive data before sending outbound.",
    },
    {
        "id": "H007",
        "severity": "HIGH",
        "category": "Webhook / Callback",
        "name": "Webhook / Callback URL",
        "description": (
            "Webhook registration or outbound callback — can post enterprise data "
            "to external services."
        ),
        "pattern": re.compile(
            r'(?i)(webhook[_\-]?url|callback[_\-]?url|notify[_\-]?url|hook[_\-]?url)'
            r'\s*[=:]\s*["\']https?://'
        ),
        "advice": "Validate and allowlist all webhook destinations.",
    },
    {
        "id": "H008",
        "severity": "HIGH",
        "category": "Cloud Storage",
        "name": "Cloud Storage Upload",
        "description": (
            "Direct upload to S3/GCS/Azure Blob — could exfiltrate data to an "
            "attacker-controlled bucket."
        ),
        "pattern": re.compile(
            r'(?i)(s3\.put_object|s3\.upload_file|boto3.*\.put|gcs.*\.upload'
            r'|azure.*\.upload_blob|storage\.bucket\(\)\.file\(\)\.upload)'
        ),
        "advice": "Audit bucket names and IAM policies. Ensure uploads go to approved buckets only.",
    },
    {
        "id": "H009",
        "severity": "HIGH",
        "category": "Data Exfiltration",
        "name": "curl / wget with data flag",
        "description": "curl or wget invocation with a data-upload flag — commonly used to POST data outbound.",
        "pattern": re.compile(
            r'(?i)\b(curl|wget)\b.*(-d\s|--data|--upload-file|-T\s|--post-data|--post-file)'
        ),
        "advice": "Review all curl/wget calls. Ensure no sensitive data is being posted outbound.",
    },
    {
        "id": "H010",
        "severity": "HIGH",
        "category": "Data Exfiltration",
        "name": "Netcat / Socat",
        "description": "Netcat or Socat — classic data exfiltration and reverse-shell tools.",
        "pattern": re.compile(r'(?i)\b(nc|ncat|netcat|socat)\b.*(-e\s|/bin/|EXEC:)'),
        "advice": "Block nc/socat at the OS/network layer. Investigate any usage in source.",
    },

    # ══════════════════════════════════════════════════════════════════════════
    # MEDIUM
    # ══════════════════════════════════════════════════════════════════════════

    {
        "id": "M001",
        "severity": "MEDIUM",
        "category": "Telemetry / Analytics",
        "name": "Third-party Telemetry / Analytics SDK",
        "description": "Analytics/telemetry SDK that sends runtime data to a third-party service.",
        "pattern": re.compile(
            r'(?i)(amplitude|mixpanel|segment\.io|heap\.io|fullstory|logrocket|datadog'
            r'|newrelic|sentry\.io|bugsnag|rollbar|honeycomb|posthog|pendo)'
        ),
        "advice": "Confirm these SDKs are approved. Review what data they collect and where it's sent.",
    },
    {
        "id": "M002",
        "severity": "MEDIUM",
        "category": "AI / LLM",
        "name": "LLM / AI API Call",
        "description": "Data may be sent to an external AI provider (OpenAI, Anthropic, etc.).",
        "pattern": re.compile(
            r'(?i)(openai\.com|api\.anthropic\.com|generativelanguage\.googleapis\.com'
            r'|api\.cohere\.ai|api\.mistral\.ai|huggingface\.co/api)'
        ),
        "advice": "Ensure no PII or confidential data is included in LLM prompts. Review data retention policies.",
    },
    {
        "id": "M003",
        "severity": "MEDIUM",
        "category": "Environment / Config",
        "name": "Sensitive Environment Variable Read",
        "description": (
            "Reading env vars with sensitive-sounding names — ensure these "
            "aren't logged or exfiltrated."
        ),
        "pattern": re.compile(
            r'(?i)(os\.environ\.get|os\.getenv|process\.env|System\.getenv)'
            r'\s*\(\s*["\']'
            r'(.*?(secret|password|passwd|token|key|credential|api)[^"\']*)["\']'
        ),
        "advice": "Ensure env vars are not logged, serialised, or included in outbound payloads.",
    },
    {
        "id": "M004",
        "severity": "MEDIUM",
        "category": "File System",
        "name": "File Read near Network Call",
        "description": (
            "File read operation in close proximity to a network call — "
            "possible exfiltration pattern."
        ),
        "pattern": re.compile(
            r'(?i)(open\(|readFile|file\.read|Files\.readAll|io\.ReadFile)'
            r'.{0,200}(requests\.|fetch\(|http\.|urllib|axios|got\.|node-fetch)',
            re.DOTALL,
        ),
        "advice": "Review if file contents are included in outbound HTTP requests.",
    },
    {
        "id": "M005",
        "severity": "MEDIUM",
        "category": "Encoding / Obfuscation",
        "name": "Hex / URL Encoding of Data",
        "description": "Hex or URL encoding — sometimes used to obfuscate exfiltrated payloads.",
        "pattern": re.compile(
            r'(?i)(binascii\.hexlify|\.encode\(["\']hex["\']\)|urllib\.parse\.quote'
            r'|encodeURIComponent\(|hex\.EncodeToString)'
        ),
        "advice": "Audit encoding calls to confirm no sensitive data is encoded before transmission.",
    },
    {
        "id": "M006",
        "severity": "MEDIUM",
        "category": "Network",
        "name": "FTP / SFTP Transfer",
        "description": "FTP or SFTP usage — may exfiltrate files to an external server.",
        "pattern": re.compile(r'(?i)(ftplib|paramiko|sftp|pysftp|FTPClient|JSch|Net::FTP)'),
        "advice": "Review FTP/SFTP endpoints. Prefer internal object storage with audit logging.",
    },
    {
        "id": "M007",
        "severity": "MEDIUM",
        "category": "Network",
        "name": "SMTP / Email Sending",
        "description": "Email sending code — can be used to exfiltrate data via email.",
        "pattern": re.compile(
            r'(?i)(smtplib|nodemailer|sendgrid|mailgun|ses\.send|smtp\.send|ActionMailer)'
        ),
        "advice": "Audit email recipients and body construction. Ensure no sensitive data is included.",
    },
    {
        "id": "M008",
        "severity": "MEDIUM",
        "category": "Serialisation",
        "name": "Insecure Deserialisation",
        "description": "Pickle or Java native deserialisation — can execute arbitrary code on load.",
        "pattern": re.compile(
            r'(?i)(pickle\.loads|pickle\.load|ObjectInputStream|readObject\(\))'
        ),
        "advice": "Avoid pickle for untrusted data. Use JSON or protobuf with schema validation.",
    },

    # ══════════════════════════════════════════════════════════════════════════
    # LOW
    # ══════════════════════════════════════════════════════════════════════════

    {
        "id": "L001",
        "severity": "LOW",
        "category": "Network",
        "name": "External IP Address Literal",
        "description": "Hardcoded public IP — may point to an external or attacker-controlled server.",
        # Excludes RFC-1918 / loopback / broadcast ranges
        "pattern": re.compile(
            r'\b(?!10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|0\.0\.0\.0|255\.255\.)'
            r'(\d{1,3}\.){3}\d{1,3}\b'
        ),
        "advice": "Replace with DNS names or configuration. Verify the IP is an approved endpoint.",
    },
    {
        "id": "L002",
        "severity": "LOW",
        "category": "Telemetry / Analytics",
        "name": "Telemetry Enabled Flag",
        "description": "Telemetry enabled flag set to true — usage data may be sent externally.",
        "pattern": re.compile(
            r'(?i)(telemetry|analytics|tracking)\s*[=:]\s*(true|enabled|1|"true"|\'true\')'
        ),
        "advice": "Confirm telemetry is intentional and approved. Review what data is sent.",
    },
    {
        "id": "L003",
        "severity": "LOW",
        "category": "Logging",
        "name": "Sensitive Variable Logged",
        "description": "Log statement that references a sensitive-sounding variable name.",
        "pattern": re.compile(
            r'(?i)(log|print|console\.log|logger\.\w+)\s*\(.*?(password|secret|token|credential|api_key)'
        ),
        "advice": "Ensure sensitive values are masked or redacted in logs.",
    },
    {
        "id": "L004",
        "severity": "LOW",
        "category": "Network",
        "name": "TLS Verification Disabled",
        "description": "SSL/TLS certificate verification disabled — traffic can be intercepted.",
        "pattern": re.compile(
            r'(?i)(verify\s*=\s*False|ssl_verify\s*=\s*False|InsecureRequestWarning'
            r'|checkCertificate\s*=\s*false|insecureSkipVerify\s*:\s*true'
            r'|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["\']0["\'])'
        ),
        "advice": "Never disable TLS verification in production. Use proper certificate chains.",
    },

    # ══════════════════════════════════════════════════════════════════════════
    # INFO
    # ══════════════════════════════════════════════════════════════════════════

    {
        "id": "I001",
        "severity": "INFO",
        "category": "Network",
        "name": "localhost / Loopback Reference",
        "description": "Loopback address — low risk, but confirms network activity exists in this file.",
        "pattern": re.compile(r'(?i)(localhost|127\.0\.0\.1|::1)'),
        "advice": (
            "Generally safe; confirm this is not dynamically replaced with an "
            "external host at runtime."
        ),
    },
    {
        "id": "I002",
        "severity": "INFO",
        "category": "Comment",
        "name": "Security-related TODO / FIXME",
        "description": "Developer note referencing security — may indicate incomplete hardening.",
        "pattern": re.compile(
            r'(?i)(#|//|/\*)\s*(todo|fixme|hack|xxx|note)'
            r'.*?(secret|auth|token|password|security|key)'
        ),
        "advice": "Resolve outstanding security TODOs before production deployment.",
    },
]
