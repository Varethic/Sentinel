<div align="center">

# Sentinel

**Defensive SAST & Passive HTTP Security Auditor**

Static analysis of full-stack web and container sources for injection sinks and misconfigurations, plus deep passive security-header and surface auditing of live responses — with zero offensive capability.

[![Python](https://img.shields.io/badge/python-3.11%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Rules](https://img.shields.io/badge/rules-172-informational)](src/json)
[![Scope](https://img.shields.io/badge/scope-defensive%20%2F%20passive-blue)](#safety-model)

</div>

---

## 1. Overview

Sentinel answers one question about a web application: **does its code and its HTTP surface follow defensive security practice?**

It operates in two complementary, strictly non-destructive ways:

| Capability | Mechanism | Input |
|---|---|---|
| **Static analysis (SAST)** | Python `ast` traversal plus pattern analysis across full-stack web & container files (`.py`, `.js`, `.ts`, `.jsx`, `.tsx`, `.php`, `.html`, `.env`, `Dockerfile`, `docker-compose.yml`) | local file or directory |
| **Passive web surface audit** | Deep same-origin multi-page inspection (up to 25 pages) with inert reflection probing and passive CVE correlation | one operator-supplied URL |

There is deliberately **no exploitation engine**: no offensive payload generation, no fuzzing, no brute forcing, and no mutating HTTP requests (`POST`/`PUT`/`DELETE`). Source is parsed or pattern-matched, never imported or executed. Web surface audits issue read-only `GET` requests to same-origin pages and inspect response metadata, security headers, cookies, and inert reflection canaries (`<sentinelprobe>`).

Detection logic is **data-driven**. Every rule — its OWASP category, CWE ID, severity, detection pattern, remediation example, reference CVE, and publication date — lives in a JSON document under `src/json/` and is validated with Pydantic at load time.

### Architecture

```text
                                   ┌──────────────────────────────────────┐
                                   │            sentinel CLI              │
                                   │  sentinel <target> (url or path)     │
                                   │  sentinel changed  (git changed)     │
                                   │  sentinel audit-code <path>          │
                                   │  sentinel audit-headers <url>        │
                                   │  sentinel rules                      │
                                   └───────────────┬──────────────────────┘
                                                   │
                        ┌──────────────────────────┴───────────────────────────┐
                        │                      src/                            │
                        │                                                      │
   ┌────────────────────┴───────────────────┐     ┌────────────────────────────┴──┐
   │  analyzers/   (detection)              │     │  core/   (plumbing)           │
   │                                        │     │                               │
   │  sqli.py, xss.py, cmdi.py,             │     │  engine.py                    │
   │  traversal.py, secrets.py, ssrf.py,    │────▶│    Finding model              │
   │  deserial.py, xxe.py, ssti.py, auth.py,│     │    Visitor base & suppressions│
   │  redos.py, api.py, deps.py, host.py,   │     │    file traversal, dedupe     │
   │  idor.py, cloud.py, client.py, tamper, │     │                               │
   │  logic.py, cve.py, webfile.py          │     │  loader.py                    │
   │                (AST & file analyzers)  │     │    Pydantic rule schema       │
   │                                        │     │    cached JSON validation     │
   │  headers.py   (deep passive web audit) │     │                               │
   │        reads sinks, patterns,          │     │                               │
   │        keywords at runtime             │◀────│                               │
   └────────────────────┬───────────────────┘     └───────────────┬───────────────┘
                        │                                         │
                        │  findings                               │  rules
                        ▼                                         ▼
   ┌────────────────────────────────────┐          ┌──────────────────────────────┐
   │  reporters/   (output)             │          │  json/   (rule data)         │
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
| `sentinel rules [--show]` | Validate and list every loaded rule document with CWE, CVE, and date. |

Common options: `--format cli|json|sarif`, `--output FILE`, `--fail-on none|low|medium|high|critical`, `--no-color`. URL commands support `--timeout SECONDS`, `--no-redirects`, `--deep/--no-deep`, `--probe/--no-probe`, and `--verbose`. `audit-code` supports `--changed` / `-c`, `--exclude DIR`, and `--quiet`.

---

## 5. Safety Model & Legal Disclaimer

* Static analysis parses source with `ast` or pattern matchers; it never imports, executes, or evaluates scanned code.
* URL auditing sends ordinary read-only `GET` requests only. No payloads, no fuzzing, no brute force, and **no `POST`/`PUT`/`PATCH`/`DELETE`** — no remote state is ever mutated.
* Deep inspection crawls up to **25 same-origin pages** (`MAX_PAGES = 25`, `MAX_DISCOVERED_LINKS = 100`) strictly matching the supplied scheme, host, and port.
* Reflection probing uses inert text (`<sentinelprobe>` and an alphanumeric canary) placed only in query parameters already provided by the operator; it contains no quotes, scripts, or SQL metacharacters.
* Polite `User-Agent` (`sentinel-auditor/<version>`) is sent with every request.
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
