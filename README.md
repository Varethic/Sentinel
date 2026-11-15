<div align="center">

# Sentinel

**Defensive Security Auditor & Vulnerability Assessment CLI**

Preliminary security auditing, defensive gap analysis, passive HTTP header evaluation, and authorized active vulnerability assessment.

[![Version](https://img.shields.io/badge/version-1.3-blue.svg)](changelog.md)
[![Python](https://img.shields.io/badge/python-3.11%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-informational)](https://github.com/Varethic/Sentinel)
[![License: Strict Security](https://img.shields.io/badge/license-Strict%20Defensive%20Security-red)](LICENSE)
[![Scope](https://img.shields.io/badge/scope-defensive%20%2F%20authorized%20auditing-green)](#safety-model)

</div>

---

## 1. Overview & Defensive Scope

Sentinel answers one critical question: **Does a web application follow defensive security best practices and secure coding standards?**

> [!IMPORTANT]
> **Strictly for Authorized & Defensive Use Only:**
> This tool performs preliminary security assessments and educational defensive research to help administrators and developers identify vulnerabilities and apply remediations before deployment. **Unauthorized scanning, offensive attacks, and malicious exploitation are strictly prohibited** under the terms of the Sentinel Strict Security License.

### Core Capabilities

* **Cross-Platform**: Full native support for **Linux**, **macOS**, and **Windows**.
* **Zero-Configuration Interactive Mode**: Simply run `sentinel` to enter an interactive session.
* **Continuous Scanning**: Audit one target, inspect findings, and press `Enter` to scan another target.
* **Dual-Team Architecture**: Concurrently executes passive surface auditing (blue team) and active vulnerability probing (red team).
* **Authenticated Scanning**: Supports `--bearer <token>`, `-H`/`--header`, and `-b`/`--cookie` for auditing protected endpoints.
* **Automated Code Remediation**: Generate Git-compatible unified diffs and safely fix vulnerabilities in-place with `sentinel fix`.
* **CI/CD Security Gate**: Headless DevSecOps gate with `sentinel ci` supporting configurable `--fail-on` and standard SARIF v2.1.0 export.
* **Actionable Remediation Guidance**: Every identified gap is paired with concrete OWASP Top 10 (2021/2023) and CWE mitigation instructions.
* **Static Source Analysis (SAST)**: 172 data-driven rules validated against Pydantic schemas.

---

## 2. Quickstart & Usage

### Installation

```bash
git clone https://github.com/Varethic/Sentinel.git
cd Sentinel
python -m venv .venv

# Activate venv:
# Linux / macOS:
source .venv/bin/activate
# Windows:
.venv\Scripts\activate

pip install -e .
```

### CLI Commands

Sentinel provides clean interactive, CI/CD, and auto-fix interfaces:

```bash
# 1. Interactive Mode (No arguments required)
$ sentinel

# 2. Direct Target & Authenticated Web Audit
$ sentinel example.com
$ sentinel example.com --bearer "eyJhbGciOi..."
$ sentinel example.com -H "Authorization: Token xyz" -b "session=abc123"

# 3. DevSecOps CI/CD Gate (Exits with code 1 on blocking findings)
$ sentinel ci src/ --fail-on high --sarif results.sarif
$ sentinel ci http://localhost:8000 --fail-on medium --json report.json

# 4. Automated Code Remediation & Patching
$ sentinel fix src/                     # Preview unified diff (dry-run)
$ sentinel fix src/ --write             # Apply safe patches directly to disk
$ sentinel fix src/ --rule CMDI002      # Patch only specific rule

# 5. Rule Catalog, Version & Info
$ sentinel rules
$ sentinel --version
$ sentinel --info
```

### Interactive Session Walkthrough

```text
╭────────────────── Sentinel Defensive Security Auditor v1.2 ──────────────────╮
│ Preliminary audit & educational defense. Prohibits unauthorized attacks.      │
╰───────────────────────────────────────────────────────────────────────────────╯

Enter target domain or URL (or 'exit' to quit): example.com

[■■■■■■■■■■■■■■■■■■■■] blue team (passive audit) 1/1 (0.8s)
[■■■■■■■■■■■■■■■■■■■■] red team (active payloads) 1/1 (1.4s)

                              Url Target : example.com                              
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Vulnerability                   ┃  Status  ┃ Endpoint                            ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ SQL Injection                   │   Pass   │ -                                   │
│ Cross-Site Scripting (XSS)      │   Pass   │ -                                   │
│ Command Injection               │   Pass   │ -                                   │
│ Path Traversal (LFI)            │   Pass   │ -                                   │
│ Server-Side Template Injection  │   Pass   │ -                                   │
│ XML External Entity             │   Pass   │ -                                   │
│ Server-Side Request Forgery     │   Pass   │ -                                   │
│ Header Spoofing                 │   Pass   │ -                                   │
│ CORS Misconfiguration           │   Pass   │ -                                   │
│ JWT Broken Verification         │   Pass   │ -                                   │
│ Mass Assignment                 │   Pass   │ -                                   │
│ API Exposure / BOLA             │   Pass   │ -                                   │
│ Insecure Deserialization        │   Pass   │ -                                   │
│ DOM XSS                         │   Pass   │ -                                   │
│ Open Redirect                   │   Pass   │ -                                   │
│ Info Disclosure                 │   Pass   │ -                                   │
│ Weak PRNG Token                 │   Pass   │ -                                   │
│ HTTP Security Headers           │  Medium  │ Content-Security-Policy missing, ...│
└─────────────────────────────────┴──────────┴─────────────────────────────────────┘

╭──────────────── Remediation Guidance & Defensive Best Practices ────────────────╮
│ HTTP Security Headers (CWE-693 / OWASP A05:2021)                                │
│   • Fix: Configure Content-Security-Policy, HSTS, and X-Content-Type-Options.    │
│   • Defense: Ensure all cookies include Secure, HttpOnly, and SameSite flags.   │
╰─────────────────────────────────────────────────────────────────────────────────╯

Press Enter to scan another target (or type 'exit' to quit)...
```

---

## 3. Audited Vulnerability Categories

All audit categories are referenced against authoritative cybersecurity standards:

| Category | Reference | Core Mitigation |
|---|---|---|
| **SQL Injection** | CWE-89 / OWASP A03:2021 | Parameterized queries & prepared statements; avoid query string concatenation. |
| **Cross-Site Scripting (XSS)** | CWE-79 / OWASP A03:2021 | Context-aware output encoding; enforce strict Content Security Policy (CSP). |
| **Command Injection** | CWE-78 / OWASP A03:2021 | Avoid shell execution; pass argument arrays with `shell=False`. |
| **Path Traversal (LFI)** | CWE-22 / OWASP A01:2021 | Canonical path verification; strict base directory validation. |
| **SSTI** | CWE-1336 / OWASP A03:2021 | Isolate user data in template context variables; enable engine sandboxes. |
| **XXE** | CWE-611 / OWASP A05:2021 | Disable XML external entity resolution and DTD processing. |
| **SSRF** | CWE-918 / OWASP A10:2021 | Strict destination URL validation; block RFC 1918 and link-local IP ranges. |
| **Header Spoofing** | CWE-345 / OWASP A07:2021 | Strip untrusted `X-Forwarded-*` headers at edge reverse proxies. |
| **CORS Misconfiguration** | CWE-942 / OWASP A01:2021 | Reject wildcards on authenticated routes; allowlist trusted origins. |
| **JWT Verification** | CWE-345 / OWASP A07:2021 | Explicit algorithm allowlists; reject the `none` algorithm. |
| **Mass Assignment** | CWE-915 / OWASP API6:2023 | Explicit DTO/Schema validation; reject administrative attributes from clients. |
| **BOLA / IDOR** | CWE-284 / OWASP API1:2023 | Object-level authorization checks validating caller identity against record ID. |
| **Insecure Deserialization** | CWE-502 / OWASP A08:2021 | Use pure data serialization (JSON) with HMAC integrity validation. |
| **DOM XSS** | CWE-79 / OWASP A03:2021 | Use safe DOM properties (`textContent`) or sanitize via DOMPurify. |
| **Open Redirect** | CWE-601 / OWASP A01:2021 | Allowlist relative destination paths; validate external redirect domains. |
| **Information Disclosure** | CWE-200 / OWASP A05:2021 | Suppress verbose error stack traces; block sensitive paths (`.git`, `.env`). |
| **Weak PRNG Token** | CWE-330 / OWASP A02:2021 | Use cryptographically secure pseudorandom generators (`secrets` module). |
| **Security Headers** | CWE-693 / OWASP A05:2021 | Deploy CSP, HSTS, X-Content-Type-Options, and secure cookie attributes. |

---

## 4. Safety Model & Legal Policy

* **Educational & Defensive Scope**: Sentinel is designed solely to audit security posture and educate engineers on defensive remediations.
* **Zero Telemetry**: No scan data, telemetry, or targets are transmitted anywhere outside the operator's machine.
* **Cross-Platform Compatibility**: Tested and verified on Windows, Linux, and macOS.
* **Strict Ethical License**: All usage is governed by the [LICENSE](LICENSE) which explicitly forbids unauthorized offensive use.

   │                                    │          │                              │
   │  terminal.py   Clean plain-text    │          │  22 rule documents           │
   │                terminal output with│          │  172 total security rules    │
   │                zero-flag summaries │          │  rule_id, name, category,    │
   │  json.py       CI/CD envelope      │          │  cwe_id, severity, desc,     │
   │  sarif.py      SARIF v2.1.0 output │          │  cve, cve_date, remediation  │
   └────────────────────────────────────┘          └──────────────────────────────┘

                    ▼ data flow:  target ──▶ analyzers ──▶ Finding ──▶ reporter ──▶ exit code
```

```text
Sentinel/
├── .github/workflows/sentinel.yml
├── .pre-commit-hooks.yaml
├── src/
│   ├── core/{engine,loader}.py
│   ├── analyzers/{sqli,xss,cmdi,traversal,secrets,ssrf,deserial,xxe,ssti,auth,redos,api,deps,host,idor,cloud,client,tamper,logic,cve,webfile,headers}.py
│   ├── active/{__init__,discover,sqli}.py
│   ├── json/{sqli,xss,cmdi,traversal,secrets,ssrf,deserial,xxe,ssti,auth,redos,api,deps,host,idor,cloud,client,tamper,logic,cve,webfile,headers,whitelist}.json
│   ├── reporters/{terminal,json,sarif}.py
│   └── cli.py
├── pyproject.toml
└── README.md
```

---

## 2. Ruleset Coverage

Sentinel enforces **172 rules across twenty-two documents** covering 20 foundational CWE categories and 100% of the OWASP Top 10. Every rule cites a reference CVE and its official NVD publication date.

| Document | Analyzer | Rules | Primary CWEs | Scope & Detects |
|---|---|:---:|---|---|
| `src/json/sqli.json` | `sqli` | 5 | CWE-89 | SQL injection sinks, string interpolation, unparameterized queries |
| `src/json/xss.json` | `xss` | 4 | CWE-79 | Cross-site scripting sinks, `mark_safe`, unescaped template strings |
| `src/json/cmdi.json` | `cmdi` | 3 | CWE-78, CWE-95 | Shell injection, `subprocess` with `shell=True`, dynamic `eval`/`exec` |
| `src/json/traversal.json` | `traversal` | 3 | CWE-22 | Path traversal, arbitrary file access, destructive file deletion |
| `src/json/secrets.json` | `secrets` | 3 | CWE-798, CWE-327, CWE-338 | Hardcoded API keys/passwords, weak MD5/SHA1, weak pseudo-randomness |
| `src/json/ssrf.json` | `ssrf` | 2 | CWE-918 | Server-side request forgery, cloud metadata IP access (`169.254.169.254`) |
| `src/json/deserial.json` | `deserial` | 2 | CWE-502 | Insecure deserialization via pickle, marshal, shelve, unsafe YAML |
| `src/json/xxe.json` | `xxe` | 2 | CWE-611 | XML external entity expansion in stdlib `xml` and `lxml` parsers |
| `src/json/ssti.json` | `ssti` | 1 | CWE-1336 | Server-side template injection via dynamic template source strings |
| `src/json/auth.json` | `auth` | 3 | CWE-295, CWE-347, CWE-489 | Disabled TLS verification, unverified JWT signatures, debug mode |
| `src/json/headers.json` | `headers` | 14 | CWE-1021, CWE-319, CWE-693, CWE-942, CWE-601 | Security headers, cookies (`HttpOnly`, `Secure`, `SameSite`), CORS, tracebacks |
| `src/json/redos.json` | `redos` | 2 | CWE-1333, CWE-400 | Regular expression denial of service, unbounded outbound requests |
| `src/json/api.json` | `api` | 2 | CWE-915, CWE-200 | GraphQL introspection enabled, mass assignment on ORM models |
| `src/json/deps.json` | `deps` | 2 | CWE-477, CWE-327 | Deprecated standard library modules, withdrawn TLS 1.0/1.1 protocols |
| `src/json/host.json` | `host` | 3 | CWE-644, CWE-444 | Host header injection, password reset poisoning, unkeyed cache poisoning |
| `src/json/idor.json` | `idor` | 3 | CWE-639, CWE-284 | Insecure direct object references, unauthenticated admin routes |
| `src/json/cloud.json` | `cloud` | 3 | CWE-350, CWE-200 | Hardcoded public cloud storage buckets, subdomain takeover indicators |
| `src/json/client.json` | `client` | 3 | CWE-922, CWE-1021, CWE-345 | Sensitive tokens in `localStorage`, reverse tabnabbing (`target="_blank"`) |
| `src/json/tamper.json` | `tamper` | 5 | CWE-307, CWE-472, CWE-650, CWE-235 | Missing rate-limiting, hidden field tampering, HTTP verb tampering |
| `src/json/logic.json` | `logic` | 2 | CWE-362, CWE-840 | Race conditions on balances/counters, financial input boundary checks |
| `src/json/cve.json` | `cve` | 100 | Multi-CWE (A06) | Curated 100-CVE vulnerability intelligence (50 CRITICAL + 50 HIGH) |
| `src/json/webfile.json` | `webfile` | 5 | CWE-79, CWE-798, CWE-94, CWE-250, CWE-829 | Full-stack JS/TS/PHP injection, leaked `.env` secrets, container privileges |
| **Total** | **22 Analyzers** | **172** | **20 Foundational CWEs** | **100% OWASP Web / API / Client Coverage** |

### Data-Driven Architecture & Custom Rules

Rule definitions decouple detection patterns from Python code. To add a custom rule, append a validated JSON object to the relevant file in `src/json/` without modifying analyzer code:

```json
{
  "rule_id": "SQLI006",
  "name": "Dynamic ORDER BY interpolation",
  "category": "A03:2021 - Injection",
  "cwe_id": "CWE-89",
  "severity": "HIGH",
  "description": "Sort direction is interpolated into the ORDER BY clause.",
  "remediation_example": "Allow-list: 'DESC' if desc else 'ASC'",
  "patterns": { "sinks": ["execute"], "sql_keywords": ["order by"] },
  "tags": ["database"],
  "references": ["https://owasp.org/Top10/A03_2021-Injection/"],
  "enabled": true
}
```

---

## 3. Installation & CLI Usage

```bash
git clone https://github.com/Varethic/Sentinel.git
cd Sentinel
python -m venv .venv && . .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -e .
sentinel --version
```

Requires **Python 3.11+**.

### Shorthand Zero-Flag Auditing

Sentinel automatically distinguishes URLs from local filesystem paths:

```bash
# Deep passive web audit (inspects headers, markup, and up to 25 same-origin links)
$ sentinel https://example.com

# Static analysis across source directory
$ sentinel src

# Scan git modified/staged files only
$ sentinel changed

# Validate rule definitions
$ sentinel rules
```

### Active SQL Injection Verification (Opt-In)

For your own lab or a target you are explicitly authorized to test, Sentinel can confirm injection rather than infer it. The command is gated: it refuses to run without `--i-own-this-target` and only talks to loopback, private, or lab-style hosts unless `--allow-public` is supplied.

No parameter list is needed. The verifier reads the page, discovers GET forms, query-string links and login forms itself, then probes each parameter:

```bash
# One page: auto-discover parameters, probe them, and try the login form
$ sentinel http://192.168.1.113:8000/labs/sqli --i-own-this-target

# Site root: automatically crawls same-origin pages and tests every endpoint
$ sentinel http://192.168.1.113:8000/ --i-own-this-target

# Explicit parameter, login bypass, or machine-readable report
$ sentinel verify-sqli http://lab.local/item --param id --i-own-this-target
$ sentinel verify-sqli http://lab.local/login --login --i-own-this-target
$ sentinel verify-sqli http://lab.local/item --i-own-this-target --json report.json
```

Output stays compact — one row per confirmed technique, plus a clean/vulnerable summary:

```text
Active SQLi  /labs/sqli  (1 page, 2 endpoints, 86 requests, 4.7s)

CONFIRMED  POST /labs/sqli/login (login)  username (POST)  auth-bypass     flag captured
CONFIRMED  GET /labs/sqli            q             boolean-based   rows 6 vs 2
CONFIRMED  GET /labs/sqli            q             union-based     5 columns
summary: 2 of 2 endpoints vulnerable · 6 confirmed
```

Pages that expose no GET parameter (POST/JS-only labs) are reported under `no params` so it is clear they were crawled but had nothing safe to inject into.

The verifier sends a bounded number of read-only requests (`--budget`; auto 120 for one page, 3000 for a crawled site) with a polite delay (`--delay`). A site root (`/`) crawls automatically; pass `--no-crawl` to keep it to one page. It covers error-based disclosure, boolean inference (including single-pass keyword-filter bypass by keyword doubling), UNION projection with per-column markers, optional time-delay checks (`--time`), and login bypass. Only GET parameters and login forms are probed automatically; other POST forms (flag submission, reset, upload) are skipped so the run stays read-only. Use `--method POST --param NAME` to probe a specific POST field. Exit code `1` means at least one technique was confirmed, `0` means clean.

### Unified URL Check & Verdict Tiers

```bash
$ sentinel https://example.com
```

```text
URL : https://example.com
pages : 3 inspected (same-origin)

xss               : HARDENING NEEDED (missing CSP, missing X-Content-Type-Options, inline script exposure)
sql injection     : SAFE (no indicators detected)
headers & cookies : HARDENING NEEDED (missing HSTS, missing X-Frame-Options, +4 more)
cors & info leak  : SAFE (no indicators detected)
ssrf & redirects  : SAFE (no indicators detected)
stack & shells    : HARDENING NEEDED (disclosed backend banner via server: cloudflare)
```

Labels clearly distinguish confirmed defects from missing defence-in-depth:

| Status | Meaning | Exit Code |
|---|---|:---:|
| `VULNERABLE` | Confirmed finding: unescaped canary reflection, SQL error/stack dump, dangerous CORS with credentials, or insecure cookie flags. | `1` (Fails run) |
| `HARDENING NEEDED` | Missing defence-in-depth: absent HSTS/CSP/X-Frame-Options/Referrer-Policy, weak CSP directives, server version banners. | `0` (Passing) |
| `SAFE` | All controls properly configured; zero vulnerability signals or misconfigurations detected. | `0` (Passing) |

### 4-Layer Deep Web Surface Inspection

```text
  sentinel <url> (zero-flag deep audit)
        │
        ├─▶ Layer 1: HTTP Headers & Cookie Hardening
        │     • Transport security: HSTS, max-age >= 180 days
        │     • Content restriction: CSP directives, X-Content-Type-Options: nosniff
        │     • Framing & Isolation: X-Frame-Options, Permissions-Policy, Referrer-Policy
        │     • Cookie security: HttpOnly, Secure, SameSite flags
        │     • Caching & Rate-limiting: Cache-Control, Vary: Host, RateLimit-* headers (TMP001)
        │
        ├─▶ Layer 2: Passive HTML/DOM Markup & Subresources
        │     • CSRF protection: POST forms verified for authenticity tokens (HDR008)
        │     • Form tampering: Hidden fields checked for sensitive variables (role, price, admin) (TMP002/TMP005)
        │     • Subresource Integrity (SRI): External scripts/stylesheets verified for integrity hashes
        │     • Transport hygiene: Mixed http:// subresources and links on HTTPS pages
        │     • Takeover indicators: Dangling links to PaaS services (Heroku, GitHub Pages, Azure, S3) (CLD002)
        │     • Tabnabbing defense: External target="_blank" links verified for rel="noopener noreferrer" (CLT002)
        │
        ├─▶ Layer 3: Client-Side DOM XSS & PostMessage Sinks
        │     • DOM XSS sinks: inline <script> checked for innerHTML, document.write, eval + location.* (DOM001)
        │     • Cross-window messaging: window.addEventListener("message") audited for origin validation (DOM002)
        │     • Client storage hygiene: localStorage / sessionStorage audited for sensitive tokens/keys (CLT001)
        │
        └─▶ Layer 4: Inert Reflection Probing & CVE Banner Intelligence
              • Inert reflection: Alphanumeric canary and <sentinelprobe> tested on GET query parameters
              • Stack disclosure: Server, X-Powered-By, and X-Generator banners identified (STK001)
              • Passive CVE correlation: Disclosed software banners and sensitive setup paths matched
                against Sentinel's 100-CVE vulnerability intelligence database (cve.json)
              • Database error disclosure: Passive detection of SQL syntax errors and database stack dumps
```

Passive markup checks run across every discovered page:

| Check | Category | Result |
|---|---|---|
| `<form method="post">` without CSRF token | `ssrf & redirects` | HARDENING NEEDED |
| External `<script src>` without SRI integrity hash | `stack & shells` | HARDENING NEEDED |
| Mixed content HTTP subresources on HTTPS page | `stack & shells` | HARDENING NEEDED |
| `<input type="password">` without rate-limit protection (`TMP001`) | `headers & cookies` | HARDENING NEEDED |
| Sensitive `<input type="hidden">` exposed to tampering (`TMP002`/`TMP005`) | `ssrf & redirects` | HARDENING NEEDED |
| DOM XSS sinks (`innerHTML`, `document.write`, `eval`) in `<script>` (`DOM001`) | `xss` | HARDENING NEEDED |
| `window.addEventListener('message')` lacking origin checks (`DOM002`) | `xss` | HARDENING NEEDED |
| Dangling links to takeover-prone cloud domains (`CLD002`) | `cors & info leak` | HARDENING NEEDED |
| External `target="_blank"` links lacking `rel="noopener noreferrer"` (`CLT002`) | `cors & info leak` | HARDENING NEEDED |
| Sensitive tokens/passwords stored in `localStorage` (`CLT001`) | `cors & info leak` | HARDENING NEEDED |
| Disclosed server banners matching known CVE catalog (`cve.json`) | `stack & shells` | VULNERABLE / HARDENING |

---

## 4. Production AppSec Workflows

### Website & Domain Whitelist

Sentinel provides an allowlist mechanism that bypasses crawling and probing for designated local or internal targets and filters noise from trusted third-party destinations.

Configure default domains in `src/json/whitelist.json` or place a `.sentinelwhitelist` file in your repository root:

```text
# Local development and internal hosts (.sentinelwhitelist)
localhost
127.0.0.1
*.internal.corp
staging.local
```

Allowlisted hosts short-circuit immediately without sending requests:

```bash
$ sentinel http://localhost
URL : http://localhost
status : WHITELISTED (domain matched allowlist)
```

### Inline Suppression

Suppress intentional patterns or verified false positives directly in code using `# sentinel: ignore` or `# nosec`:

```python
cursor.execute(f"SELECT * FROM {table}")  # sentinel: ignore
raw_exec(command)  # nosec
```

### Pre-Commit Hook

Add Sentinel to your `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/Varethic/Sentinel
    rev: master
    hooks:
      - id: sentinel
```

### SARIF v2.1.0 & JSON Output for CI/CD

```bash
# SARIF v2.1.0 export for GitHub Code Scanning
$ sentinel src --format sarif -o results.sarif --fail-on high

# Standard JSON export
$ sentinel src --format json -o results.json --fail-on high
```

### GitHub Actions CI/CD Gate

Ready-to-use workflow at `.github/workflows/sentinel.yml`:

```yaml
name: Sentinel Security Gate

on:
  push:
    branches: [ master ]
  pull_request:
    branches: [ master ]

jobs:
  sentinel-audit:
    name: Sentinel SAST & Ruleset Validation
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"
          cache: "pip"

      - name: Install dependencies
        run: pip install -e .

      - name: Validate Rule Documents
        run: sentinel rules

      - name: Run Sentinel SAST (SARIF export)
        run: sentinel audit-code src --format sarif -o results.sarif --fail-on high

      - name: Upload SARIF report
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif
```

### Exit Codes

| Code | Meaning |
|:---:|---|
| `0` | Clean pass or findings below threshold (default `high`). Whitelisted targets exit `0`. |
| `1` | At least one finding at or above the threshold (`HIGH` or `CRITICAL`). |
| `2` | Usage error, invalid target, or network failure (unreachable host). |

### Commands Reference

| Command | Purpose |
|---|---|
| `sentinel <target>` | Zero-flag audit: URL for deep web surface scan, or path for SAST. |
| `sentinel changed` | Audit only modified, staged, and untracked git files. |
| `sentinel audit-code <path>` | Full-stack static analysis across Python, web, and container files. |
| `sentinel audit-headers <url>` | Deep passive HTTP security header, cookie, and markup audit. |
| `sentinel <url> --i-own-this-target [--crawl]` | Opt-in active SQL injection verification with automatic parameter discovery. |
| `sentinel verify-sqli <url>` | Explicit form of the same command (`--param`, `--login`, `--json`, etc.). |
| `sentinel rules [--show]` | Validate and list every loaded rule document with CWE, CVE, and date. |

Common options: `--format cli|json|sarif`, `--output FILE`, `--fail-on none|low|medium|high|critical`, `--no-color`. URL commands support `--timeout SECONDS`, `--no-redirects`, `--deep/--no-deep`, `--probe/--no-probe`, and `--verbose`. `audit-code` supports `--changed` / `-c`, `--exclude DIR`, and `--quiet`. `verify-sqli` supports `--param/-p`, `--method GET|POST`, `--login`, `--user-field`, `--pass-field`, `--crawl`, `--no-crawl`, `--max-pages`, `--i-own-this-target` (required), `--allow-public`, `--budget`, `--delay`, `--timeout`, `--time`, `--verbose`, and `--json FILE`.

---

## 5. Safety Model & Legal Disclaimer

* Static analysis parses source with `ast` or pattern matchers; it never imports, executes, or evaluates scanned code.
* The passive URL audit sends ordinary read-only `GET` requests only. No payloads, no fuzzing, no brute force, and **no `POST`/`PUT`/`PATCH`/`DELETE`** — no remote state is ever mutated.
* Deep inspection crawls up to **25 same-origin pages** (`MAX_PAGES = 25`, `MAX_DISCOVERED_LINKS = 100`) strictly matching the supplied scheme, host, and port.
* Reflection probing uses inert text (`<sentinelprobe>` and an alphanumeric canary) placed only in query parameters already provided by the operator; it contains no quotes, scripts, or SQL metacharacters.
* Active verification is a separate, opt-in command. It requires `--i-own-this-target`, restricts targets to loopback/private/lab-style hosts unless `--allow-public` is given, caps requests with `--budget`, spaces them with `--delay`, and sends only read-only SQL predicates (`AND`/`OR`/`UNION`/`LIKE`/delay functions). No `INSERT`, `UPDATE`, `DELETE`, `DROP`, stacked writes, file writes, or command execution are ever sent. Login checks submit a bounded list of credential payloads to the operator-specified form.
* Polite `User-Agent` (`sentinel-auditor/<version>` for passive audits, `SentinelActive/0.1` for active probes) is sent with every request.
* Zero telemetry — nothing is sent anywhere except the operator-specified URL.

### Legal Disclaimer

Sentinel is provided for **defensive, authorized security testing only**. Use it exclusively against systems and code you own or operate, or for which you have explicit written authorization. The authors and copyright holders accept no liability for misuse. Software is provided "as is" under the MIT License.

### Limitations

* SAST scope: Full-stack coverage is provided across Python (`.py`, `.pyi`), JavaScript/TypeScript/React (`.js`, `.ts`, `.jsx`, `.tsx`), PHP (`.php`), HTML (`.html`), environment secrets (`.env`), and container manifests (`Dockerfile`, `docker-compose.yml`). AST-based semantic analysis applies to Python, while regex and pattern-based rule auditing applies to JS/TS/PHP/HTML and container manifests.
* Header auditing crawls up to 25 same-origin pages by default; it does not execute JavaScript and will not see headers added client-side. Pass `--no-deep` for a single-page check.
* Not a substitute for a full DAST suite or manual code review; Sentinel is designed as a fast, high-signal, zero-noise security gate.

---

## 6. Contributing & License

Contributions are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) — this project enforces single-word filenames in `src/`, a leading underscore on all functions/methods, plain-text CLI output, and non-destructive network behavior. Security issues in Sentinel itself should be reported privately as described in [SECURITY.md](SECURITY.md).

Licensed under the [MIT License](LICENSE). Copyright (c) 2026 Varethic.
