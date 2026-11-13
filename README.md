<div align="center">

# Sentinel

**Defensive SAST & Passive HTTP Security Auditor**

Static analysis of Python web sources for injection sinks, plus passive security-header
auditing of live responses — with zero offensive capability.

[![Python](https://img.shields.io/badge/python-3.11%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Rules](https://img.shields.io/badge/rules-42-informational)](src/json)
[![Scope](https://img.shields.io/badge/scope-defensive%20%2F%20passive-blue)](#safety-model)

</div>

---

## 1. Overview

Sentinel answers one question about a Python web application: **does its code and its
HTTP surface follow defensive security practice?**

It does this two ways, and only these two ways:

| Capability | Mechanism | Input |
|---|---|---|
| **Static analysis (SAST)** | Python `ast` traversal of your own source tree | local file or directory |
| **Passive header audit** | exactly one HTTP request; response metadata is inspected | one operator-supplied URL |

There is deliberately **no exploitation engine**: no payload generation, no crawling, no
fuzzing, no brute forcing, no request replay. Source is parsed, never imported or executed.
A header audit sends one ordinary `GET` and reads what comes back.

Detection logic is **data-driven**. Every rule — its OWASP category, CWE id, severity,
detection pattern, and remediation example — lives in a JSON document under `src/json/`
and is validated with Pydantic at load time. `src/core/loader.py` is the only bridge
between rule data and Python behaviour, so the analyzers contain no hardcoded policy and
the ruleset is auditable by a security reviewer without reading analyzer code.

### Architecture

```text
                                   ┌──────────────────────────────────────┐
                                   │            sentinel CLI              │
                                   │  sentinel <url>   (shorthand)        │
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
   │  sqli.py      ─┐  SQLI001..005         │     │  engine.py                    │
   │  xss.py       ─┤  XSS001..004          │────▶│    Finding model              │
   │  cmdi.py      ─┤  CMDI001..003         │     │    Visitor base               │
   │  traversal.py ─┤  PATH001..003         │     │    file traversal, dedupe     │
   │  secrets.py   ─┤  SEC001..003          │     │                               │
   │  ssrf.py      ─┤  SSRF001..002         │     │  loader.py                    │
   │  deserial.py  ─┤  DES001..002          │     │    Pydantic rule schema       │
   │  xxe.py       ─┤  XXE001..002          │     │    cached JSON validation     │
   │  ssti.py      ─┤  SSTI001              │     │                               │
   │  auth.py      ─┘  AUTH001..003         │     │                               │
   │                (AST visitors)          │     │                               │
   │                                        │     │                               │
   │  headers.py   ──  HDR001..014          │     │                               │
   │                (passive httpx)         │     │                               │
   │        reads sinks, patterns,          │     │                               │
   │        keywords at runtime             │◀────│                               │
   └────────────────────┬───────────────────┘     └───────────────┬───────────────┘
                        │                                         │
                        │  findings                               │  rules
                        ▼                                         ▼
   ┌────────────────────────────────────┐          ┌──────────────────────────────┐
   │  reporters/   (output)             │          │  json/   (rule data)         │
   │                                    │          │                              │
   │  terminal.py   Rich tables,        │          │  sqli.json      5 rules      │
   │                severity colours,   │          │  xss.json       4 rules      │
   │                compact 4-category  │          │  cmdi.json      3 rules      │
   │                URL summary         │          │  traversal.json 3 rules      │
   │                                    │          │  secrets.json   3 rules      │
   │  json.py       CI/CD envelope,     │          │  rule_id, name, category,    │
   │                summary, blocking   │          │  cwe_id, severity, desc,     │
   │                                    │          │  remediation_example         │
   └────────────────────────────────────┘          └──────────────────────────────┘

                    ▼ data flow:  target ──▶ analyzers ──▶ Finding ──▶ reporter ──▶ exit code
```

```text
Sentinel/
├── src/
│   ├── core/{engine,loader}.py
│   ├── analyzers/{sqli,xss,cmdi,traversal,secrets,headers}.py
│   ├── json/{sqli,xss,cmdi,traversal,secrets,headers}.json
│   ├── reporters/{terminal,json}.py
│   └── cli.py
├── pyproject.toml
└── README.md
```

---

## 2. Ruleset coverage

42 rules across eleven documents. Severity drives the CI gate: **HIGH** and **CRITICAL**
findings fail a run by default.

| Document | Analyzer | Rules | Scope |
|---|---|---:|---|
| `src/json/sqli.json` | `sqli` | 5 | SQL injection sinks |
| `src/json/xss.json` | `xss` | 4 | cross-site scripting sinks |
| `src/json/cmdi.json` | `cmdi` | 3 | shell command injection, dynamic `eval`/`exec` |
| `src/json/traversal.json` | `traversal` | 3 | path traversal, destructive file operations |
| `src/json/secrets.json` | `secrets` | 3 | hardcoded credentials, weak hashes, weak randomness |
| `src/json/ssrf.json` | `ssrf` | 2 | server-side request forgery, cloud metadata access |
| `src/json/deserial.json` | `deserial` | 2 | pickle/marshal/shelve and unsafe YAML deserialization |
| `src/json/xxe.json` | `xxe` | 2 | XML external entity expansion (stdlib and lxml) |
| `src/json/ssti.json` | `ssti` | 1 | template source built from dynamic input |
| `src/json/auth.json` | `auth` | 3 | disabled TLS verification, unverified JWT, debug mode |
| `src/json/headers.json` | `headers` | 14 | passive HTTP header, cookie, CORS, redirect and disclosure checks |

### SQL injection — `src/json/sqli.json`

| Rule | Severity | OWASP Top 10 (2021) | CWE | Detects |
|---|:---:|---|---|---|
| `SQLI001` | **CRITICAL** | A03 Injection | [CWE-89](https://cwe.mitre.org/data/definitions/89.html) | f-string interpolated into `.execute()` / `.executemany()` / `.executescript()` |
| `SQLI002` | **CRITICAL** | A03 Injection | CWE-89 | `+` string concatenation into a SQL sink |
| `SQLI003` | HIGH | A03 Injection | CWE-89 | `%` percent-formatting into a SQL sink |
| `SQLI004` | HIGH | A03 Injection | CWE-89 | `str.format()` / `string.Template.substitute()` into a SQL sink |
| `SQLI005` | HIGH | A03 Injection | CWE-89 | ORM `text()` / `raw()` given interpolated SQL |

Parameterized forms are recognised and never reported: `execute(sql, params)`,
named bindings (`:id`), `text(...).bindparams(...)`, and positional `?` placeholders.

### Cross-site scripting — `src/json/xss.json`

| Rule | Severity | OWASP Top 10 (2021) | CWE | Detects |
|---|:---:|---|---|---|
| `XSS001` | HIGH | A03 Injection | [CWE-79](https://cwe.mitre.org/data/definitions/79.html) | `Markup()` / `mark_safe()` applied to dynamic, unescaped content |
| `XSS002` | HIGH | A03 Injection | CWE-79 | `render_template_string()` / `from_string()` with a dynamic template source |
| `XSS003` | MEDIUM | A02 Cryptographic Failures | CWE-79 | `autoescape=False` / `select_autoescape(default=False)`, `safe` on dynamic data |
| `XSS004` | HIGH | A03 Injection | CWE-79 | HTML response body assembled by interpolation |

Values wrapped in `escape()` / `markupsafe.escape` / `bleach` are treated as sanitized.

### Command injection — `src/json/cmdi.json`

| Rule | Severity | OWASP Top 10 (2021) | CWE | Detects |
|---|:---:|---|---|---|
| `CMDI001` | **CRITICAL** | A03 Injection | [CWE-78](https://cwe.mitre.org/data/definitions/78.html) | `os.system()` / `os.popen()` given an f-string, `+`, `%`, `.format()` or `Template` command |
| `CMDI002` | **CRITICAL** | A03 Injection | CWE-78 | `subprocess.run/Popen/call/check_output` with `shell=True` and a dynamic command |
| `CMDI003` | HIGH | A03 Injection | [CWE-95](https://cwe.mitre.org/data/definitions/95.html) | `eval()` / `exec()` on a non-literal argument |

Not reported: literal commands (`os.system("ls -l")`), argument lists
(`subprocess.run(["ls", name])`), and `ast.literal_eval(...)`.

### Path traversal — `src/json/traversal.json`

| Rule | Severity | OWASP Top 10 (2021) | CWE | Detects |
|---|:---:|---|---|---|
| `PATH001` | HIGH | A01 Broken Access Control | [CWE-22](https://cwe.mitre.org/data/definitions/22.html) | `open()` / `pathlib.Path()` given a dynamic path with no visible normalisation |
| `PATH002` | **CRITICAL** | A01 Broken Access Control | CWE-22 | `os.remove` / `unlink` / `rmdir` / `shutil.rmtree` given a dynamic path |
| `PATH003` | HIGH | A01 Broken Access Control | CWE-22 | `send_file` / `send_from_directory` / `FileResponse` serving a dynamic path |

A path is considered mitigated when the expression applies `resolve()`,
`relative_to()`, `os.path.basename/realpath/normpath`, `werkzeug.secure_filename` or
`safe_join` — including when the guard wraps the value (`Path(x).resolve()`).

### Hardcoded secrets & weak crypto — `src/json/secrets.json`

| Rule | Severity | OWASP Top 10 (2021) | CWE | Detects |
|---|:---:|---|---|---|
| `SEC001` | **CRITICAL** | A02 Cryptographic Failures | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) | `API_KEY` / `SECRET_KEY` / `PASSWORD` / `AWS_SECRET` / `JWT_SECRET` / `PRIVATE_KEY` assigned a real string literal |
| `SEC002` | HIGH | A02 Cryptographic Failures | [CWE-327](https://cwe.mitre.org/data/definitions/327.html) | `hashlib.md5()` / `sha1()` without `usedforsecurity=False` |
| `SEC003` | MEDIUM | A02 Cryptographic Failures | [CWE-338](https://cwe.mitre.org/data/definitions/338.html) | `random.random/randint/choice/...` feeding a token, password, session or nonce |

`SEC001` stays quiet for placeholders (`""`, `"changeme"`, `"example"`), for values loaded
via `os.getenv()` / `os.environ` / `config.*`, and for metadata names
(`API_KEY_ENV`, `SECRET_KEY_PATH`, `PASSWORD_FIELD`).

### HTTP headers & cookies — `src/json/headers.json`

| Rule | Severity | OWASP Top 10 (2021) | CWE | Detects |
|---|:---:|---|---|---|
| `HDR001` | HIGH | A05 Misconfiguration | [CWE-1021](https://cwe.mitre.org/data/definitions/1021.html) | Missing / weak `Content-Security-Policy` (`unsafe-inline`, `unsafe-eval`, `*`, missing `default-src`/`object-src`/`base-uri`) |
| `HDR002` | HIGH | A02 Cryptographic Failures | [CWE-319](https://cwe.mitre.org/data/definitions/319.html) | Missing `Strict-Transport-Security`, or `max-age` < 180 days |
| `HDR003` | MEDIUM | A05 Misconfiguration | [CWE-693](https://cwe.mitre.org/data/definitions/693.html) | Missing or non-`nosniff` `X-Content-Type-Options` |
| `HDR004` | MEDIUM | A05 Misconfiguration | CWE-1021 | No frame protection (`X-Frame-Options` or CSP `frame-ancestors`) |
| `HDR005` | LOW | A05 Misconfiguration | [CWE-200](https://cwe.mitre.org/data/definitions/200.html) | Missing / weak `Referrer-Policy` (`unsafe-url`, `no-referrer-when-downgrade`) |
| `HDR006` | LOW | A05 Misconfiguration | CWE-693 | Missing `Permissions-Policy` |
| `HDR007` | LOW | A05 Misconfiguration | CWE-200 | Version disclosure via `Server`, `X-Powered-By`, `X-AspNet-Version`, … |
| `HDR008` | MEDIUM | A07 Auth Failures | [CWE-1004](https://cwe.mitre.org/data/definitions/1004.html) | Cookie without `HttpOnly` |
| `HDR009` | MEDIUM | A02 Cryptographic Failures | [CWE-614](https://cwe.mitre.org/data/definitions/614.html) | Cookie without `Secure` |
| `HDR010` | MEDIUM | A01 Broken Access Control | [CWE-1275](https://cwe.mitre.org/data/definitions/1275.html) | Cookie without `SameSite`, or `SameSite=None` without `Secure` |
| `HDR011` | **HIGH** | A05 Misconfiguration | [CWE-942](https://cwe.mitre.org/data/definitions/942.html) | `Access-Control-Allow-Origin: *` (especially with `Allow-Credentials: true`) or a reflected origin with credentials |
| `HDR012` | MEDIUM | A05 Misconfiguration | [CWE-209](https://cwe.mitre.org/data/definitions/209.html) | Debug traceback / stack trace disclosed in the response body (Python, Django, Flask/Werkzeug, SQLAlchemy) |
| `HDR013` | MEDIUM | A01 Broken Access Control | [CWE-601](https://cwe.mitre.org/data/definitions/601.html) | Same-origin link or form carrying a redirect/fetch parameter (`url`, `redirect`, `next`, `target`, `dest`, `return_to`, `callback`, …) |
| `HDR014` | **HIGH** | A05 Misconfiguration | [CWE-538](https://cwe.mitre.org/data/definitions/538.html) | Directory listing (`Index of /`) or secret-file content in the body (`DB_PASSWORD=`, `SECRET_KEY=`, `PRIVATE KEY`, `/etc/passwd`) |

### SSRF — `src/json/ssrf.json`

| Rule | Severity | OWASP Top 10 (2021) | CWE | Detects |
|---|:---:|---|---|---|
| `SSRF001` | **HIGH** | A10 SSRF | [CWE-918](https://cwe.mitre.org/data/definitions/918.html) | `requests` / `httpx` / `urllib.request` / `aiohttp` call given a URL built from an f-string, `+`, `%`, `.format()` or an unvalidated variable |
| `SSRF002` | **CRITICAL** | A10 SSRF | [CWE-918](https://cwe.mitre.org/data/definitions/918.html) | Outbound request targeting `169.254.169.254`, `metadata.google.internal` or another cloud metadata host |

Guards are recognised per function scope: `if host not in ALLOWED_HOSTS: raise ...` and
`if not is_allowed_host(host): raise ...` suppress the finding, including when `host` was
derived from the URL (`urlparse(url).hostname`).

### Insecure deserialization — `src/json/deserial.json`

| Rule | Severity | OWASP Top 10 (2021) | CWE | Detects |
|---|:---:|---|---|---|
| `DES001` | **CRITICAL** | A08 Data Integrity Failures | [CWE-502](https://cwe.mitre.org/data/definitions/502.html) | `pickle.load`/`loads`, `_pickle.loads`, `cPickle`, `marshal.loads`, `shelve.open`, `dill` on non-literal data |
| `DES002` | **HIGH** | A08 Data Integrity Failures | [CWE-502](https://cwe.mitre.org/data/definitions/502.html) | `yaml.load` / `yaml.unsafe_load` without `Loader=yaml.SafeLoader` or `CSafeLoader` |

`safe_load`, `safe_load_all` and an explicit safe `Loader=` are never reported.

### XML external entity — `src/json/xxe.json`

| Rule | Severity | OWASP Top 10 (2021) | CWE | Detects |
|---|:---:|---|---|---|
| `XXE001` | **HIGH** | A05 Misconfiguration | [CWE-611](https://cwe.mitre.org/data/definitions/611.html) | `xml.etree.ElementTree.parse/fromstring`, `xml.dom.minidom.parse/parseString`, `xml.sax.parse` on non-literal input (import aliases such as `ET` are resolved) |
| `XXE002` | **HIGH** | A05 Misconfiguration | [CWE-611](https://cwe.mitre.org/data/definitions/611.html) | `lxml.etree.XMLParser(resolve_entities=True)`, `no_network=False`, `load_dtd=True` or `dtd_validation=True` |

Anything imported from `defusedxml` is treated as safe and never reported.

### Server-side template injection — `src/json/ssti.json`

| Rule | Severity | OWASP Top 10 (2021) | CWE | Detects |
|---|:---:|---|---|---|
| `SSTI001` | **CRITICAL** | A03 Injection | [CWE-1336](https://cwe.mitre.org/data/definitions/1336.html) | `jinja2.Template`, `flask.render_template_string`, `mako.template.Template`, `django.template.Template` given a dynamic template source |

Only the template **source** is checked. `render_template('page.html', name=user)` passes
data as a variable and is never reported; a static template literal is also clean.

### Authentication, TLS and configuration — `src/json/auth.json`

| Rule | Severity | OWASP Top 10 (2021) | CWE | Detects |
|---|:---:|---|---|---|
| `AUTH001` | **HIGH** | A02 Cryptographic Failures | [CWE-295](https://cwe.mitre.org/data/definitions/295.html) | `verify=False` on a `requests`/`httpx` call, or `ssl._create_unverified_context()` |
| `AUTH002` | **CRITICAL** | A07 Auth Failures | [CWE-347](https://cwe.mitre.org/data/definitions/347.html) | `jwt.decode(..., options={"verify_signature": False})` or `verify=False` |
| `AUTH003` | **HIGH** | A05 Misconfiguration | [CWE-489](https://cwe.mitre.org/data/definitions/489.html) | `DEBUG = True` assignment, or `app.run(..., debug=True)` / `run_simple(..., debug=True)` |

### Adding a rule

Append a validated object to the relevant JSON document — no Python change is required for
data-driven fields:

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

Malformed documents fail loudly rather than being skipped: unknown keys, invalid severity,
non-`CWE-` ids, malformed `rule_id`s, duplicate ids, and broken JSON all raise
`RuleLoadError` with the source path and reason.

---

## 3. Installation & CLI usage

```bash
git clone https://github.com/Varethic/Sentinel.git
cd Sentinel
python -m venv .venv && . .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -e .
sentinel --version
```

Requires **Python 3.11+**.

### Unified URL check

`sentinel <url>` runs **all five categories in a single pass** — XSS, SQL injection,
headers & cookies, and CORS/info leak — and prints a compact three-tier summary:

```bash
$ sentinel https://example.com
```

```text
URL : https://example.com

xss               : HARDENING NEEDED (missing CSP, missing X-Content-Type-Options,
                    inline script exposure)
sql injection     : SAFE (no indicators detected)
headers & cookies : HARDENING NEEDED (missing HSTS, missing X-Frame-Options,
                    missing X-Content-Type-Options, +3 more)
cors & info leak  : SAFE (no indicators detected)
ssrf & redirects  : SAFE (no indicators detected)
```

### Verdict tiers

A passive scan cannot prove most exploits, so the labels separate *confirmed* problems
from *missing defence-in-depth*:

| Status | Colour | Meaning | Fails the run |
|---|---|:---:|:---:|
| `VULNERABLE` | **red** | A confirmed, directly observed issue: unescaped reflection actually seen in the body, a live SQL error / stack trace in the body, dangerous CORS (`*` **with** `Allow-Credentials: true`, or a reflected origin with credentials), or insecure cookie flags. | yes (`1`) |
| `HARDENING NEEDED` | **yellow** | Missing or weak defence-in-depth: absent HSTS/CSP/X-Frame-Options/Referrer-Policy/Permissions-Policy, `unsafe-inline`/`unsafe-eval` in CSP, wildcard CORS **without** credentials, `Server`/`X-Powered-By` banners, verbose debug headers. Real, worth fixing, but not proof of exploitability. | no (`0`) |
| `SAFE` | **green** | Every control for that category is configured and no confirming signal was found. | no (`0`) |

**Reflection is what confirms XSS.** The probe is sent only when the target already has a
query parameter. If the parameter comes back unescaped, `xss` is `VULNERABLE`; if the echo
is HTML-escaped, or the page has no parameters at all, a missing/weak CSP is reported as
`HARDENING NEEDED` instead — a weak CSP raises the impact of a hypothetical injection but
does not demonstrate one:

```text
xss : HARDENING NEEDED (weak CSP (unsafe-inline, unsafe-eval))
xss : VULNERABLE (unescaped reflection)          # only when actually observed
```

The exit code still follows the confirmed tier only: `1` when any category is
`VULNERABLE`, `0` otherwise (including a scan that is entirely `HARDENING NEEDED`).
A failed request exits `2`.

| Category | Confirms `VULNERABLE` | Reports `HARDENING NEEDED` |
|---|---|---|
| `xss` | Unescaped reflection of the inert probe in the body | Missing CSP, or a weak CSP listing `unsafe-inline` / `unsafe-eval`, inline script exposure with no `script-src`, missing `X-Content-Type-Options` |
| `sql injection` | Database error signature in the body (MySQL, PostgreSQL, SQLite, Oracle, ODBC, SQLSTATE, …) | Query-specific debug headers (`X-Debug-SQL-*`, `X-SQL`, `X-Query`) with no error present |
| `headers & cookies` | Insecure cookie flags (`HttpOnly`, `Secure`, `SameSite`), debug disclosure headers | Missing `HSTS`, `X-Frame-Options` (or CSP `frame-ancestors`), `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`; `Server`/`X-Powered-By` banners |
| `cors & info leak` | Debug traceback in the body, `*` + `Allow-Credentials: true`, reflected origin + credentials | Wildcard `Access-Control-Allow-Origin: *` without credentials |
| `ssrf & redirects` | Directory listing (`Index of /`) or secret-file content served in the body | Same-origin link or form exposing a redirect/fetch parameter (`url`, `redirect`, `next`, `target`, `dest`, `return_to`, `callback`, …) |

A fully hardened target reports `SAFE` on every category:

```text
xss               : SAFE (no indicators detected)
sql injection     : SAFE (no indicators detected)
headers & cookies : SAFE (no indicators detected)
cors & info leak  : SAFE (no indicators detected)
ssrf & redirects  : SAFE (no indicators detected)
```

### Multi-page and markup inspection

By default an audit fetches **one page** and inspects its markup. `--deep` follows up to
**5** discovered same-origin links before stopping:

```bash
sentinel https://example.com --deep
```

```text
URL : https://example.com
pages: 3 inspected (same-origin)

xss               : HARDENING NEEDED (missing CSP, missing X-Content-Type-Options,
                    inline script exposure, +2 more)
...
```

Markup checks run on every inspected page:

| Check | Category | Result |
|---|---|---|
| `<form method="post">` with no hidden `csrf`/`token`/`nonce`/`authenticity_token` field | `xss` | HARDENING NEEDED |
| External `<script src>` / stylesheet without `integrity=` (SRI) | `xss` | HARDENING NEEDED |
| `http://` subresource or same-origin link on an HTTPS page (mixed content) | `headers & cookies` | HARDENING NEEDED |
| `http://` form action on an HTTPS page | `headers & cookies` | HARDENING NEEDED |
| `<input type="password">` served over plain HTTP | `headers & cookies` | HARDENING NEEDED |

### Reflection probing is opt-in

Without `--probe`, the audit is fully passive: it sends one `GET` per page and **never
rewrites a query parameter**. With `--probe`, one benign request is sent per page that
already declares query parameters, using two inert markers:

* `sentinel_canary_<hex>` — purely alphanumeric, so it can never form markup, SQL
  syntax or a path traversal;
* `<sentinelprobe>` — inert angle brackets, the only way to distinguish an escaped
  echo from a raw one.

`xss` is only raised to `VULNERABLE` when `<sentinelprobe>` comes back **verbatim**. An
alphanumeric canary alone cannot prove missing encoding, because it survives HTML
escaping unchanged — so the markup marker, not the canary, is what confirms.

```bash
sentinel https://example.com --probe
```

**Detail on demand:**

```bash
sentinel https://example.com --verbose          # full severity tables + remediation
sentinel https://example.com --format json      # machine-readable categories
```

### Scan guardrails

* **GET only.** No `POST`, `PUT`, `PATCH` or `DELETE` is ever issued, so no state mutates.
* **Same-origin only.** Link and form discovery keeps the exact scheme/host/port of the
  operator-supplied URL; external and protocol-relative links are discarded.
* **Hard caps.** At most 5 pages, 40 discovered links and 25 surface findings per scan,
  plus the `--timeout` on every request.
* **Identifiable.** A polite `User-Agent` (`sentinel-auditor/<version>`) is sent.
* **Inert markers.** Probing uses `<sentinelprobe>` and an alphanumeric canary only —
  never a SQLi, CMDi, XSS or template payload.

The explicit `sentinel audit-headers <url>` command keeps its detailed table output
unchanged; the compact view is only the default for the shorthand form.

### Static analysis

```bash
$ sentinel audit-code ./src
$ sentinel audit-code app.py --fail-on critical   # exits 2 if app.py is missing
$ sentinel audit-code . --exclude vendor --exclude migrations --quiet
```

### JSON output for CI/CD

```bash
# full project report written to disk
$ sentinel audit-code ./src --format json -o sentinel.json --fail-on high

# the sample document below comes from this exact command on a small sample file
$ sentinel audit-code app.py --format json

# the shorthand web report is JSON too
$ sentinel https://staging.example.com --format json | jq '.summary'
```

Given a sample file containing three unsafe query builders, the report looks like this
(one finding shown; `total` is `3`):

```json
{
  "schema_version": "1.0.0",
  "tool": { "name": "sentinel-auditor", "version": "0.1.0" },
  "report_type": "code",
  "generated_at": "2026-01-01T00:00:00+00:00",
  "target": "app.py",
  "summary": {
    "total": 3,
    "severity_counts": { "LOW": 0, "MEDIUM": 0, "HIGH": 1, "CRITICAL": 2 },
    "blocking": 3,
    "passed": false
  },
  "findings": [
    {
      "rule_id": "SQLI001",
      "rule_name": "Unparameterized query via f-string",
      "severity": "CRITICAL",
      "category": "A03:2021 - Injection",
      "cwe_id": "CWE-89",
      "location": { "file": "app.py", "line": 6, "column": 4 },
      "message": "SQL query built with an f-string and passed to execute(); interpolated values become part of the query text",
      "code_snippet": "cursor.execute(f\"SELECT * FROM users WHERE email = '{email}'\")",
      "remediation": "cursor.execute('SELECT * FROM users WHERE email = %s', (email,))",
      "blocking": true
    }
  ],
  "scan": { "files_scanned": 1, "files_skipped": 0, "errors": [] }
}
```

### Exit codes

| Code | Meaning |
|:---:|---|
| `0` | No findings at or above `--fail-on` (default `high`). |
| `1` | At least one finding at or above the threshold. |
| `2` | Usage error, invalid target, or **no response could be audited**. |

A failed request exits `2`, never `0` — a pipeline can never mistake "host unreachable"
for "host is clean".

### GitHub Actions

```yaml
name: security
on: [push, pull_request]

jobs:
  sentinel:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.12" }
      - run: pip install -e .
      - run: sentinel audit-code ./src --format json -o sentinel.json --fail-on high
      - uses: actions/upload-artifact@v4
        if: always()
        with: { name: sentinel-report, path: sentinel.json }
```

### Commands reference

| Command | Purpose |
|---|---|
| `sentinel <url>` | Shorthand unified audit: five categories in one pass. |
| `sentinel audit-code <path>` | AST analysis of a file or directory (all 42 rules). |
| `sentinel audit-headers <url>` | Same unified URL audit, explicit form. |
| `sentinel rules [--show]` | Validate and list every loaded rule document. |

Common options: `--format cli\|json`, `--output FILE`, `--fail-on none\|low\|medium\|high\|critical`,
`--no-color`. The URL commands add `--timeout SECONDS`, `--no-redirects`, `--deep`
(follow up to 5 same-origin pages), `--probe` (opt-in inert reflection markers) and
`--verbose` (every reason, plus the inspected URLs). `audit-code` adds `--exclude DIR`
(repeatable) and `--quiet`.

---

## Safety model

* Static analysis **parses** source with `ast`; it never imports, executes, or evaluates it.
* URL auditing sends ordinary `GET` requests only. No payloads, no fuzzing, no brute force,
  and **no `POST`/`PUT`/`PATCH`/`DELETE`** — no state on the target is ever modified.
* By default one `GET` is sent to the target. `--deep` follows at most **5 same-origin**
  pages, with a hard cap on discovered links and the `--timeout` applied to every request.
* Discovered links and form actions are followed **only** when they match the exact
  scheme, host and port of the URL you supplied.
* The reflection probe is inert text (`<sentinelprobe>`) placed only in a query parameter
  the operator already supplied; it contains no script, quote, or SQL metacharacter, and
  is sent **only** with the explicit `--probe` flag.
* No `eval`, no shell, no filesystem writes, no secret material.
* No telemetry — nothing is sent anywhere except the URL you pass.

See [SECURITY.md](SECURITY.md) for the full authorized-use policy.

## Legal disclaimer

Sentinel is provided for **defensive, authorized security testing only**.

Use it exclusively against code you own or maintain, and against systems you own or
operate — or for which you hold explicit written authorisation or a bug bounty scope that
permits this class of automated testing. Because URL auditing issues real network requests
to the host you name, those requests originate from your machine and are attributable to
you.

**Do not use Sentinel against systems you do not have permission to test.** Unauthorised
scanning may violate computer-misuse laws (for example the U.S. Computer Fraud and Abuse
Act, the UK Computer Misuse Act, or equivalent legislation in your jurisdiction) and the
terms of service of the target.

The authors and copyright holders accept **no liability** for misuse, for damage arising
from use of this tool, or for any legal consequences of scanning without authorisation.
The software is provided "as is", without warranty of any kind, as set out in the
[MIT License](LICENSE).

A `SAFE` verdict means no indicators were found; it is **not** a certification that a
target is free of vulnerabilities.

## Limitations

* Python sources only for SAST (`.py`, `.pyi`). Non-Python stacks are out of scope.
* Header auditing sees one response by default. `--deep` widens this to at most 5
  same-origin pages; it does not execute JavaScript and will not see headers added
  client-side.
* `XSS002`/`XSS004` are heuristic: they follow data flow through named variables, not
  cross-module taint tracking.
* Not a substitute for a full SAST/DAST suite or manual review; it is a fast, low-noise
  first gate.

## Contributing

Contributions are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) first — this
project enforces a strict architecture (single-word filenames in `src/`, a leading
underscore on every function, plain-text CLI output, and non-destructive network
behaviour).

Security issues **in Sentinel itself** should be reported privately as described in
[SECURITY.md](SECURITY.md), not through a public issue.

## License

MIT — see [LICENSE](LICENSE). Copyright (c) 2026 Varethic.

<div align="center"><sub>Built as a defensive auditing exercise. The vulnerable example rules
are documentation fixtures and must never be copied into real systems.</sub></div>
