<div align="center">

# Sentinel

**Defensive SAST & Passive HTTP Security Auditor**

Static analysis of Python web sources for injection sinks, plus passive security-header
auditing of live responses — with zero offensive capability.

[![Python](https://img.shields.io/badge/python-3.11%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Rules](https://img.shields.io/badge/rules-172-informational)](src/json)
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
   │  terminal.py   Plain-text URL      │          │  22 rule documents           │
   │                summary, Rich       │          │  172 total security rules    │
   │                tables for details  │          │  rule_id, name, category,    │
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
│   ├── json/{sqli,xss,cmdi,traversal,secrets,ssrf,deserial,xxe,ssti,auth,redos,api,deps,host,idor,cloud,client,tamper,logic,cve,webfile,headers}.json
│   ├── reporters/{terminal,json,sarif}.py
│   └── cli.py
├── pyproject.toml
└── README.md
```

---

## 2. Ruleset coverage

172 rules across twenty-two documents. Severity drives the CI gate: **HIGH** and **CRITICAL**
findings fail a run by default. Every rule cites a reference CVE and its NVD publication date,
so a finding can be traced to a real-world instance of the same vulnerability class.

> The cited CVE **illustrates** the class of defect the rule detects; it is not a claim that
the scanned code contains that specific CVE.

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
| `src/json/redos.json` | `redos` | 2 | catastrophic regex backtracking, unbounded outbound requests |
| `src/json/api.json` | `api` | 2 | GraphQL introspection, mass assignment |
| `src/json/deps.json` | `deps` | 2 | deprecated standard-library modules, withdrawn TLS protocols |
| `src/json/host.json` | `host` | 3 | host header injection, password reset poisoning, unkeyed cache exposure |
| `src/json/idor.json` | `idor` | 3 | insecure direct object references, unauthenticated administrative routes |
| `src/json/cloud.json` | `cloud` | 3 | hardcoded public cloud storage buckets, subdomain takeover indicators |
| `src/json/client.json` | `client` | 3 | sensitive tokens in localStorage/sessionStorage, reverse tabnabbing |
| `src/json/tamper.json` | `tamper` | 5 | rate-limiting/brute-force protection, parameter tampering, HTTP verb tampering |
| `src/json/logic.json` | `logic` | 2 | race conditions in balances/counters, financial input bounds checks |
| `src/json/cve.json` | `cve` | 100 | curated 100-CVE vulnerability intelligence (50 CRITICAL + 50 HIGH) |
| `src/json/webfile.json` | `webfile` | 5 | full-stack web and container files (.js, .ts, .php, .html, .env, Dockerfile, docker-compose) |

### SQL injection — `src/json/sqli.json`

| Rule | Severity | OWASP Top 10 (2021) | CWE | Reference CVE | Detects |
|---|:---:|---|---|---|
| `SQLI001` | **CRITICAL** | A03 Injection | [CWE-89](https://cwe.mitre.org/data/definitions/89.html) | `CVE-2022-28346` (2022-04-12) | f-string interpolated into `.execute()` / `.executemany()` / `.executescript()` |
| `SQLI002` | **CRITICAL** | A03 Injection | CWE-89 | `CVE-2019-14234` (2019-08-09) | `+` string concatenation into a SQL sink |
| `SQLI003` | HIGH | A03 Injection | CWE-89 | `CVE-2020-7471` (2020-02-03) | `%` percent-formatting into a SQL sink |
| `SQLI004` | HIGH | A03 Injection | CWE-89 | `CVE-2022-34265` (2022-07-04) | `str.format()` / `string.Template.substitute()` into a SQL sink |
| `SQLI005` | HIGH | A03 Injection | CWE-89 | `CVE-2022-28346` (2022-04-12) | ORM `text()` / `raw()` given interpolated SQL |

Parameterized forms are recognised and never reported: `execute(sql, params)`,
named bindings (`:id`), `text(...).bindparams(...)`, and positional `?` placeholders.

### Cross-site scripting — `src/json/xss.json`

| Rule | Severity | OWASP Top 10 (2021) | CWE | Reference CVE | Detects |
|---|:---:|---|---|---|
| `XSS001` | HIGH | A03 Injection | [CWE-79](https://cwe.mitre.org/data/definitions/79.html) | `CVE-2020-11022` (2020-04-29) | `Markup()` / `mark_safe()` applied to dynamic, unescaped content |
| `XSS002` | HIGH | A03 Injection | CWE-79 | `CVE-2019-11358` (2019-04-20) | `render_template_string()` / `from_string()` with a dynamic template source |
| `XSS003` | MEDIUM | A02 Cryptographic Failures | CWE-79 | `CVE-2020-11022` (2020-04-29) | `autoescape=False` / `select_autoescape(default=False)`, `safe` on dynamic data |
| `XSS004` | HIGH | A03 Injection | CWE-79 | `CVE-2018-1000136` (2018-03-23) | HTML response body assembled by interpolation |

Values wrapped in `escape()` / `markupsafe.escape` / `bleach` are treated as sanitized.

### Command injection — `src/json/cmdi.json`

| Rule | Severity | OWASP Top 10 (2021) | CWE | Reference CVE | Detects |
|---|:---:|---|---|---|
| `CMDI001` | **CRITICAL** | A03 Injection | [CWE-78](https://cwe.mitre.org/data/definitions/78.html) | `CVE-2021-42740` (2021-10-21) | `os.system()` / `os.popen()` given an f-string, `+`, `%`, `.format()` or `Template` command |
| `CMDI002` | **CRITICAL** | A03 Injection | CWE-78 | `CVE-2021-42740` (2021-10-21) | `subprocess.run/Popen/call/check_output` with `shell=True` and a dynamic command |
| `CMDI003` | HIGH | A03 Injection | [CWE-95](https://cwe.mitre.org/data/definitions/95.html) | `CVE-2022-21699` (2022-01-19) | `eval()` / `exec()` on a non-literal argument |

Not reported: literal commands (`os.system("ls -l")`), argument lists
(`subprocess.run(["ls", name])`), and `ast.literal_eval(...)`.

### Path traversal — `src/json/traversal.json`

| Rule | Severity | OWASP Top 10 (2021) | CWE | Reference CVE | Detects |
|---|:---:|---|---|---|
| `PATH001` | HIGH | A01 Broken Access Control | [CWE-22](https://cwe.mitre.org/data/definitions/22.html) | `CVE-2021-41773` (2021-10-05) | `open()` / `pathlib.Path()` given a dynamic path with no visible normalisation |
| `PATH002` | **CRITICAL** | A01 Broken Access Control | CWE-22 | `CVE-2021-41773` (2021-10-05) | `os.remove` / `unlink` / `rmdir` / `shutil.rmtree` given a dynamic path |
| `PATH003` | HIGH | A01 Broken Access Control | CWE-22 | `CVE-2019-20916` (2020-09-04) | `send_file` / `send_from_directory` / `FileResponse` serving a dynamic path |

A path is considered mitigated when the expression applies `resolve()`,
`relative_to()`, `os.path.basename/realpath/normpath`, `werkzeug.secure_filename` or
`safe_join` — including when the guard wraps the value (`Path(x).resolve()`).

### Hardcoded secrets & weak crypto — `src/json/secrets.json`

| Rule | Severity | OWASP Top 10 (2021) | CWE | Reference CVE | Detects |
|---|:---:|---|---|---|
| `SEC001` | **CRITICAL** | A02 Cryptographic Failures | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) | `CVE-2018-1000656` (2018-08-20) | `API_KEY` / `SECRET_KEY` / `PASSWORD` / `AWS_SECRET` / `JWT_SECRET` / `PRIVATE_KEY` assigned a real string literal |
| `SEC002` | HIGH | A02 Cryptographic Failures | [CWE-327](https://cwe.mitre.org/data/definitions/327.html) | `CVE-2021-3177` (2021-01-19) | `hashlib.md5()` / `sha1()` without `usedforsecurity=False` |
| `SEC003` | MEDIUM | A02 Cryptographic Failures | [CWE-338](https://cwe.mitre.org/data/definitions/338.html) | `CVE-2020-10735` (2022-09-09) | `random.random/randint/choice/...` feeding a token, password, session or nonce |

`SEC001` stays quiet for placeholders (`""`, `"changeme"`, `"example"`), for values loaded
via `os.getenv()` / `os.environ` / `config.*`, and for metadata names
(`API_KEY_ENV`, `SECRET_KEY_PATH`, `PASSWORD_FIELD`).

### HTTP headers & cookies — `src/json/headers.json`

| Rule | Severity | OWASP Top 10 (2021) | CWE | Reference CVE | Detects |
|---|:---:|---|---|---|
| `HDR001` | HIGH | A05 Misconfiguration | [CWE-1021](https://cwe.mitre.org/data/definitions/1021.html) | `CVE-2020-11022` (2020-04-29) | Missing / weak `Content-Security-Policy` (`unsafe-inline`, `unsafe-eval`, `*`, missing `default-src`/`object-src`/`base-uri`) |
| `HDR002` | HIGH | A02 Cryptographic Failures | [CWE-319](https://cwe.mitre.org/data/definitions/319.html) | `CVE-2021-21290` (2021-02-08) | Missing `Strict-Transport-Security`, or `max-age` < 180 days |
| `HDR003` | MEDIUM | A05 Misconfiguration | [CWE-693](https://cwe.mitre.org/data/definitions/693.html) | `CVE-2019-7742` (2019-02-12) | Missing or non-`nosniff` `X-Content-Type-Options` |
| `HDR004` | MEDIUM | A05 Misconfiguration | CWE-1021 | `CVE-2021-28861` (2022-08-23) | No frame protection (`X-Frame-Options` or CSP `frame-ancestors`) |
| `HDR005` | LOW | A05 Misconfiguration | [CWE-200](https://cwe.mitre.org/data/definitions/200.html) | `CVE-2021-32640` (2021-05-25) | Missing / weak `Referrer-Policy` (`unsafe-url`, `no-referrer-when-downgrade`) |
| `HDR006` | LOW | A05 Misconfiguration | CWE-693 | `CVE-2022-35256` (2022-12-05) | Missing `Permissions-Policy` |
| `HDR007` | LOW | A05 Misconfiguration | CWE-200 | `CVE-2023-25690` (2023-03-07) | Version disclosure via `Server`, `X-Powered-By`, `X-AspNet-Version`, … |
| `HDR008` | MEDIUM | A07 Auth Failures | [CWE-1004](https://cwe.mitre.org/data/definitions/1004.html) | `CVE-2018-1000656` (2018-08-20) | Cookie without `HttpOnly` |
| `HDR009` | MEDIUM | A02 Cryptographic Failures | [CWE-614](https://cwe.mitre.org/data/definitions/614.html) | `CVE-2020-28491` (2021-02-18) | Cookie without `Secure` |
| `HDR010` | MEDIUM | A01 Broken Access Control | [CWE-1275](https://cwe.mitre.org/data/definitions/1275.html) | `CVE-2019-10744` (2019-07-26) | Cookie without `SameSite`, or `SameSite=None` without `Secure` |
| `HDR011` | **HIGH** | A05 Misconfiguration | [CWE-942](https://cwe.mitre.org/data/definitions/942.html) | `CVE-2020-8116` (2020-02-04) | `Access-Control-Allow-Origin: *` (especially with `Allow-Credentials: true`) or a reflected origin with credentials |
| `HDR012` | MEDIUM | A05 Misconfiguration | [CWE-209](https://cwe.mitre.org/data/definitions/209.html) | `CVE-2022-21699` (2022-01-19) | Debug traceback / stack trace disclosed in the response body (Python, Django, Flask/Werkzeug, SQLAlchemy) |
| `HDR013` | MEDIUM | A01 Broken Access Control | [CWE-601](https://cwe.mitre.org/data/definitions/601.html) | `CVE-2021-28861` (2022-08-23) | Same-origin link or form carrying a redirect/fetch parameter (`url`, `redirect`, `next`, `target`, `dest`, `return_to`, `callback`, …) |
| `HDR014` | **HIGH** | A05 Misconfiguration | [CWE-538](https://cwe.mitre.org/data/definitions/538.html) | `CVE-2021-41773` (2021-10-05) | Directory listing (`Index of /`) or secret-file content in the body (`DB_PASSWORD=`, `SECRET_KEY=`, `PRIVATE KEY`, `/etc/passwd`) |

### SSRF — `src/json/ssrf.json`

| Rule | Severity | OWASP Top 10 (2021) | CWE | Reference CVE | Detects |
|---|:---:|---|---|---|
| `SSRF001` | **HIGH** | A10 SSRF | [CWE-918](https://cwe.mitre.org/data/definitions/918.html) | `CVE-2023-24329` (2023-02-17) | `requests` / `httpx` / `urllib.request` / `aiohttp` call given a URL built from an f-string, `+`, `%`, `.format()` or an unvalidated variable |
| `SSRF002` | **CRITICAL** | A10 SSRF | [CWE-918](https://cwe.mitre.org/data/definitions/918.html) | `CVE-2019-9740` (2019-03-13) | Outbound request targeting `169.254.169.254`, `metadata.google.internal` or another cloud metadata host |

Guards are recognised per function scope: `if host not in ALLOWED_HOSTS: raise ...` and
`if not is_allowed_host(host): raise ...` suppress the finding, including when `host` was
derived from the URL (`urlparse(url).hostname`).

### Insecure deserialization — `src/json/deserial.json`

| Rule | Severity | OWASP Top 10 (2021) | CWE | Reference CVE | Detects |
|---|:---:|---|---|---|
| `DES001` | **CRITICAL** | A08 Data Integrity Failures | [CWE-502](https://cwe.mitre.org/data/definitions/502.html) | `CVE-2020-14343` (2021-02-09) | `pickle.load`/`loads`, `_pickle.loads`, `cPickle`, `marshal.loads`, `shelve.open`, `dill` on non-literal data |
| `DES002` | **HIGH** | A08 Data Integrity Failures | [CWE-502](https://cwe.mitre.org/data/definitions/502.html) | `CVE-2017-18342` (2018-06-27) | `yaml.load` / `yaml.unsafe_load` without `Loader=yaml.SafeLoader` or `CSafeLoader` |

`safe_load`, `safe_load_all` and an explicit safe `Loader=` are never reported.

### XML external entity — `src/json/xxe.json`

| Rule | Severity | OWASP Top 10 (2021) | CWE | Reference CVE | Detects |
|---|:---:|---|---|---|
| `XXE001` | **HIGH** | A05 Misconfiguration | [CWE-611](https://cwe.mitre.org/data/definitions/611.html) | `CVE-2022-48565` (2023-08-22) | `xml.etree.ElementTree.parse/fromstring`, `xml.dom.minidom.parse/parseString`, `xml.sax.parse` on non-literal input (import aliases such as `ET` are resolved) |
| `XXE002` | **HIGH** | A05 Misconfiguration | [CWE-611](https://cwe.mitre.org/data/definitions/611.html) | `CVE-2022-48565` (2023-08-22) | `lxml.etree.XMLParser(resolve_entities=True)`, `no_network=False`, `load_dtd=True` or `dtd_validation=True` |

Anything imported from `defusedxml` is treated as safe and never reported.

### Server-side template injection — `src/json/ssti.json`

| Rule | Severity | OWASP Top 10 (2021) | CWE | Reference CVE | Detects |
|---|:---:|---|---|---|
| `SSTI001` | **CRITICAL** | A03 Injection | [CWE-1336](https://cwe.mitre.org/data/definitions/1336.html) | `CVE-2021-29510` (2021-05-13) | `jinja2.Template`, `flask.render_template_string`, `mako.template.Template`, `django.template.Template` given a dynamic template source |

Only the template **source** is checked. `render_template('page.html', name=user)` passes
data as a variable and is never reported; a static template literal is also clean.

### Authentication, TLS and configuration — `src/json/auth.json`

| Rule | Severity | OWASP Top 10 (2021) | CWE | Reference CVE | Detects |
|---|:---:|---|---|---|
| `AUTH001` | **HIGH** | A02 Cryptographic Failures | [CWE-295](https://cwe.mitre.org/data/definitions/295.html) | `CVE-2018-1000805` (2018-10-08) | `verify=False` on a `requests`/`httpx` call, or `ssl._create_unverified_context()` |
| `AUTH002` | **CRITICAL** | A07 Auth Failures | [CWE-347](https://cwe.mitre.org/data/definitions/347.html) | `CVE-2021-32677` (2021-06-09) | `jwt.decode(..., options={"verify_signature": False})` or `verify=False` |
| `AUTH003` | **HIGH** | A05 Misconfiguration | [CWE-489](https://cwe.mitre.org/data/definitions/489.html) | `CVE-2021-37678` (2021-08-12) | `DEBUG = True` assignment, or `app.run(..., debug=True)` / `run_simple(..., debug=True)` |

### ReDoS & resource exhaustion — `src/json/redos.json`

| Rule | Severity | OWASP Top 10 (2021) | CWE | Reference CVE | Detects |
|---|:---:|---|---|---|---|
| `DOS001` | HIGH | A04 Insecure Design | [CWE-1333](https://cwe.mitre.org/data/definitions/1333.html) | `CVE-2020-7662` (2020-06-02) | `re.compile()`/`search()`/`match()` given a literal pattern with nested quantifiers (`(a+)+`, `(.*)+`, `([a-zA-Z]+)*`), overlapping alternation, or a `{1000,}` repetition |
| `DOS002` | MEDIUM | A04 Insecure Design | [CWE-400](https://cwe.mitre.org/data/definitions/400.html) | `CVE-2021-33503` (2021-06-29) | `requests`/`httpx`/`urllib`/`urllib3` call with no `timeout=` |

`DOS001` deliberately requires a **literal** pattern. A pattern held in a variable or built at
runtime cannot be judged statically, so it is not reported rather than guessed at.

### API & GraphQL — `src/json/api.json`

| Rule | Severity | OWASP Top 10 (2021) | CWE | Reference CVE | Detects |
|---|:---:|---|---|---|---|
| `API001` | MEDIUM | A01 Broken Access Control | [CWE-200](https://cwe.mitre.org/data/definitions/200.html) | `CVE-2022-31129` (2022-07-06) | `introspection=True` passed to a Graphene/Strawberry/Ariadne `Schema` |
| `API002` | HIGH | A01 Broken Access Control | [CWE-915](https://cwe.mitre.org/data/definitions/915.html) | `CVE-2022-22965` (2022-04-01) | `Model(**request.json())` / `Model(**await request.json())` |

`API001` resolves the import map first, so `from graphene import Schema` followed by
`Schema(introspection=True)` is caught while an unrelated class that merely happens to be
called `Schema` is not.

### Deprecated & insecure modules — `src/json/deps.json`

| Rule | Severity | OWASP Top 10 (2021) | CWE | Reference CVE | Detects |
|---|:---:|---|---|---|---|
| `DEP001` | MEDIUM | A06 Outdated Components | [CWE-477](https://cwe.mitre.org/data/definitions/477.html) | `CVE-2021-3177` (2021-01-19) | `import` of `telnetlib`, `ftplib`, `cgi`, `imp`, `pickletools`, `asynchat`, `asyncore`, `smtpd`, `distutils` |
| `DEP002` | HIGH | A02 Cryptographic Failures | [CWE-327](https://cwe.mitre.org/data/definitions/327.html) | `CVE-2021-28861` (2022-08-23) | `ssl.PROTOCOL_TLSv1`, `PROTOCOL_TLSv1_1`, `PROTOCOL_SSLv3`, `PROTOCOL_SSLv23` |

`DEP001` reports each module once per file. `DEP002` only fires when the constant is reached
through `ssl`, so an unrelated attribute that shares the name is not flagged.

### Host header injection & cache poisoning — `src/json/host.json`

| Rule | Severity | OWASP Top 10 (2021) | CWE | Reference CVE | Detects |
|---|:---:|---|---|---|---|
| `HST001` | **HIGH** | A01 Broken Access Control | [CWE-644](https://cwe.mitre.org/data/definitions/644.html) | `CVE-2023-25690` (2023-03-07) | Trusting raw `Host` or `X-Forwarded-Host` request headers in Python handlers to build redirects or reset links |
| `HST002` | MEDIUM | A05 Misconfiguration | [CWE-444](https://cwe.mitre.org/data/definitions/444.html) | `CVE-2023-32314` (2023-05-19) | Unkeyed cache/proxy headers (`X-Cache`, `CF-Cache-Status`, `Age`, `Via`) combined with missing `Vary: Host` |
| `HST003` | **CRITICAL** | A01 Broken Access Control | [CWE-644](https://cwe.mitre.org/data/definitions/644.html) | `CVE-2021-32796` (2021-08-04) | Host header password reset poisoning via outgoing email |

`HST001` inspects AST string formatting and URL construction for direct header reads without allowlist validation.
`HST002` inspects live response headers for missing cache keys.
`HST003` flags password-reset handlers embedding unvalidated Host headers into email bodies.

### IDOR & broken access control — `src/json/idor.json`

| Rule | Severity | OWASP Top 10 (2021) | CWE | Reference CVE | Detects |
|---|:---:|---|---|---|---|
| `IDR001` | **HIGH** | A01 Broken Access Control | [CWE-639](https://cwe.mitre.org/data/definitions/639.html) | `CVE-2023-28432` (2023-03-22) | Route handler accepting object identifier (`user_id`, `account_id`, `order_id`) passed directly to ORM lookup without auth guard |
| `IDR002` | **HIGH** | A01 Broken Access Control | [CWE-284](https://cwe.mitre.org/data/definitions/284.html) | `CVE-2022-24765` (2022-04-12) | Sensitive admin or internal route (`/admin`, `/internal`, `/debug`, `/metrics`) defined without auth decorators |
| `IDR003` | **CRITICAL** | A01 Broken Access Control | [CWE-639](https://cwe.mitre.org/data/definitions/639.html) | `CVE-2023-38039` (2023-07-26) | Direct object update or delete mutating tenant records without tenant ID scoping |

`IDR001` flags object queries lacking session/user scoping. `IDR002` flags unauthenticated router endpoints.
`IDR003` flags mutative database operations lacking multi-tenant boundary checks.

### Cloud storage & subdomain takeover — `src/json/cloud.json`

| Rule | Severity | OWASP Top 10 (2021) | CWE | Reference CVE | Detects |
|---|:---:|---|---|---|---|
| `CLD001` | **HIGH** | A01 Broken Access Control | [CWE-200](https://cwe.mitre.org/data/definitions/200.html) | `CVE-2021-3156` (2021-01-26) | Hardcoded public cloud storage bucket URL (`s3.amazonaws.com`, `storage.googleapis.com`, `blob.core.windows.net`) |
| `CLD002` | **HIGH** | A05 Misconfiguration | [CWE-350](https://cwe.mitre.org/data/definitions/350.html) | `CVE-2022-23614` (2022-02-11) | External resource or markup link pointing to takeover-prone cloud domain (`*.herokuapp.com`, `*.github.io`, `*.azurewebsites.net`) |
| `CLD003` | **CRITICAL** | A01 Broken Access Control | [CWE-200](https://cwe.mitre.org/data/definitions/200.html) | `CVE-2020-8910` (2020-03-24) | Unauthenticated cloud instance metadata access (`169.254.169.254`) in client-facing handlers |

`CLD001` inspects source code for hardcoded bucket endpoints. `CLD002` inspects HTML subresources for dangling PaaS references.
`CLD003` catches unauthenticated handlers fetching internal instance metadata.

### Client-side storage & reverse tabnabbing — `src/json/client.json`

| Rule | Severity | OWASP Top 10 (2021) | CWE | Reference CVE | Detects |
|---|:---:|---|---|---|---|
| `CLT001` | **HIGH** | A04 Insecure Design | [CWE-922](https://cwe.mitre.org/data/definitions/922.html) | `CVE-2021-3918` (2021-11-04) | Storing sensitive credential or token (`token`, `jwt`, `secret`, `password`) in `localStorage`/`sessionStorage` |
| `CLT002` | MEDIUM | A01 Broken Access Control | [CWE-1021](https://cwe.mitre.org/data/definitions/1021.html) | `CVE-2020-8127` (2020-02-04) | External link with `target="_blank"` missing `rel="noopener"` or `rel="noreferrer"` (Reverse Tabnabbing) |
| `CLT003` | **HIGH** | A04 Insecure Design | [CWE-345](https://cwe.mitre.org/data/definitions/345.html) | `CVE-2022-35918` (2022-08-01) | Unvalidated `window.addEventListener('message')` event listener accepting untrusted origins |

`CLT001` flags script storage leaks. `CLT002` flags unpinned new-tab navigation anchors.
`CLT003` flags DOM message listeners without `event.origin` verification.

### Rate-limiting & request tampering — `src/json/tamper.json`

| Rule | Severity | OWASP Top 10 (2021) | CWE | Reference CVE | Detects |
|---|:---:|---|---|---|---|
| `TMP001` | **HIGH** | A07 Auth Failures | [CWE-307](https://cwe.mitre.org/data/definitions/307.html) | `CVE-2022-24785` (2022-04-04) | Authentication routes (`/login`, `/token`, `/otp`, `/reset-password`) missing rate-limiting decorators or throttling |
| `TMP002` | **HIGH** | A04 Insecure Design | [CWE-472](https://cwe.mitre.org/data/definitions/472.html) | `CVE-2021-32677` (2021-06-11) | Trusting sensitive privilege or financial fields (`role`, `is_admin`, `price`, `amount`) directly from untrusted request bodies/cookies |
| `TMP003` | **HIGH** | A04 Insecure Design | [CWE-650](https://cwe.mitre.org/data/definitions/650.html) | `CVE-2023-25690` (2023-03-07) | Reading `X-HTTP-Method-Override` / `X-Method-Override` or handling mixed GET/POST mutations in a single handler |
| `TMP004` | MEDIUM | A04 Insecure Design | [CWE-235](https://cwe.mitre.org/data/definitions/235.html) | `CVE-2022-29217` (2022-05-24) | HTTP parameter pollution across duplicate query parameter reads |
| `TMP005` | MEDIUM | A04 Insecure Design | [CWE-472](https://cwe.mitre.org/data/definitions/472.html) | `CVE-2021-41773` (2021-10-05) | Insecure client state reflection or sensitive fields in hidden HTML form fields |

`TMP001` flags unthrottled brute-force avenues. `TMP002` flags unauthenticated privilege assignment.
`TMP003` detects verb tampering and method overrides. `TMP004` and `TMP005` detect parameter pollution and hidden field tampering.

### Race conditions & business logic — `src/json/logic.json`

| Rule | Severity | OWASP Top 10 (2021) | CWE | Reference CVE | Detects |
|---|:---:|---|---|---|---|
| `LGC001` | **CRITICAL** | A04 Insecure Design | [CWE-362](https://cwe.mitre.org/data/definitions/362.html) | `CVE-2023-32314` (2023-05-19) | Read-modify-write on account balances, inventory, or coupon counters without transactional locking (`select_for_update`, `with transaction:`, `Lock()`) |
| `LGC002` | **HIGH** | A04 Insecure Design | [CWE-840](https://cwe.mitre.org/data/definitions/840.html) | `CVE-2022-24785` (2022-04-04) | Financial or quantity input (`amount`, `price`, `quantity`, `balance`) parsed from request without positive bounds validation (`<= 0`) |

`LGC001` detects Time-of-Check to Time-of-Use (TOCTOU) race conditions in stateful financial operations.
`LGC002` catches negative-value parameter injection and integer underflow logic flaws in payment flows.

### 100-CVE vulnerability intelligence — `src/json/cve.json`

Sentinel includes an integrated knowledge base of **100 high-impact web and API vulnerabilities** (50 **CRITICAL** + 50 **HIGH**), indexed from `CVE001` through `CVE100`.

| Metric | Details |
|---|---|
| **Coverage** | Exactly 50 CRITICAL + 50 HIGH severity CVEs across Web Applications, Frameworks, CMS, APIs, and Web Servers |
| **Catalog Scope** | Spring Framework (Spring4Shell), Log4j (Log4Shell), Apache Struts, Confluence OGNL, GitLab RCE, Jenkins CLI, Apache HTTP Server, Nginx, Django, Flask, Rails, Werkzeug, F5 BIG-IP, Citrix ADC, Fortinet, Grafana, MinIO, Kibana, GeoServer, SolarWinds, TeamCity, Atlassian Bitbucket, and more |
| **Dual-Mode Detection** | **SAST**: Detects vulnerable dependency versions and vulnerable code patterns in manifest files (`requirements.txt`, `Pipfile`, `pyproject.toml`) and Python imports.<br>**Web Surface**: Automatically correlates disclosed HTTP `Server`, `X-Powered-By`, and `X-Generator` banners, plus exposed administrative or setup paths, against known exploitable CVE signatures during passive audits. |
| **Data Integrity** | 100% verified NVD publication dates, CVSS scores, remediation advisories, and CWE classifications. |

### Full-stack web & container security — `src/json/webfile.json`

| Rule | Severity | OWASP Top 10 (2021) | CWE | Reference CVE | Detects |
|---|:---:|---|---|---|---|
| `WEB001` | **HIGH** | A03 Injection | [CWE-79](https://cwe.mitre.org/data/definitions/79.html) | `CVE-2020-11022` (2020-04-29) | Unsafe DOM/React XSS sinks (`dangerouslySetInnerHTML`, `innerHTML =`, `outerHTML =`, `document.write(`, `eval(`) in `.js`, `.ts`, `.jsx`, `.tsx`, and `.html` files |
| `WEB002` | **CRITICAL** | A02 Cryptographic Failures | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) | `CVE-2023-28432` (2023-03-22) | Hardcoded API keys, tokens, or database credentials committed inside `.env`, `.js`, `.ts`, `.php`, `Dockerfile` (`ENV`/`ARG`), or `docker-compose.yml` files (ignoring `.env.example` / `.env.template` placeholder values) |
| `WEB003` | **CRITICAL** | A03 Injection | [CWE-94](https://cwe.mitre.org/data/definitions/94.html) | `CVE-2024-4577` (2024-06-06) | Unsafe PHP RCE/shell sinks (`eval($_`, `shell_exec($_`, `system($_`, `passthru($_`, `exec($_`) in `.php` files |
| `WEB004` | **HIGH** | A04 Insecure Design | [CWE-250](https://cwe.mitre.org/data/definitions/250.html) | `CVE-2024-21626` (2024-01-31) | `Dockerfile` configurations running as `USER root` or missing a non-root `USER` instruction |
| `WEB005` | **MEDIUM** | A06 Outdated Components | [CWE-829](https://cwe.mitre.org/data/definitions/829.html) | `CVE-2021-44228` (2021-12-10) | `Dockerfile` instructions using remote `ADD http://` or unpinned `:latest` base images |

`WEB001` inspects client-side templates and scripts for raw DOM injection vectors.
`WEB002` scans environment variables, secrets declarations, and container compose manifests with placeholder filtering.
`WEB003` flags remote code execution in PHP web handlers.
`WEB004` and `WEB005` enforce container least privilege and supply chain immutability.

### 20-CWE Complete OWASP Web/API/Client Coverage

Sentinel maps 100% of its 172 rules across 20 foundational CWE categories:

| # | CWE ID | Category Name | Sentinel Rule Documents | Rule IDs | OWASP Top 10 |
|---|---|---|---|---|---|
| 1 | CWE-89 | SQL Injection | `sqli.json`, `headers.json` | `SQLI001`-`SQLI005`, Passive | A03:2021 Injection |
| 2 | CWE-79 | Cross-Site Scripting (Reflected, Stored, DOM) | `xss.json`, `headers.json`, `webfile.json` | `XSS001`-`XSS004`, `DOM001`-`DOM002`, `WEB001` | A03:2021 Injection |
| 3 | CWE-78, CWE-94, CWE-95 | Command & Code Injection | `cmdi.json`, `webfile.json` | `CMDI001`-`CMDI003`, `WEB003` | A03:2021 Injection |
| 4 | CWE-22 | Path Traversal & Arbitrary File Access | `traversal.json` | `PATH001`-`PATH003` | A01:2021 Broken Access Control |
| 5 | CWE-798 | Hardcoded Credentials & Secrets | `secrets.json`, `webfile.json` | `SEC001`, `WEB002` | A02:2021 Cryptographic Failures |
| 6 | CWE-327, CWE-338 | Weak Cryptography & Weak PRNG | `secrets.json`, `deps.json` | `SEC002`, `SEC003`, `DEP002` | A02:2021 Cryptographic Failures |
| 7 | CWE-918 | Server-Side Request Forgery (SSRF) | `ssrf.json`, `headers.json` | `SSRF001`-`SSRF002`, `HDR013` | A10:2021 Server-Side Request Forgery |
| 8 | CWE-502 | Insecure Deserialization | `deserial.json` | `DES001`-`DES002` | A08:2021 Software and Data Integrity Failures |
| 9 | CWE-611 | XML External Entity (XXE) Injection | `xxe.json` | `XXE001`-`XXE002` | A05:2021 Security Misconfiguration |
| 10 | CWE-1336 | Server-Side Template Injection (SSTI) | `ssti.json` | `SSTI001` | A03:2021 Injection |
| 11 | CWE-295, CWE-347 | TLS Verification & JWT Signature Bypass | `auth.json` | `AUTH001`-`AUTH002` | A02:2021 Cryptographic Failures / A07 Auth |
| 12 | CWE-489, CWE-200, CWE-693 | Debug Mode & Missing Security Headers | `auth.json`, `headers.json` | `AUTH003`, `HDR001`-`HDR007` | A05:2021 Security Misconfiguration |
| 13 | CWE-1333, CWE-400 | ReDoS & Resource Exhaustion | `redos.json` | `DOS001`-`DOS002` | A04:2021 Insecure Design |
| 14 | CWE-915, CWE-200 | API Mass Assignment & Introspection | `api.json` | `API001`-`API002` | A01:2021 Broken Access Control |
| 15 | CWE-477 | Obsolete & Insecure Standard Modules | `deps.json` | `DEP001` | A06:2021 Vulnerable and Outdated Components |
| 16 | CWE-644, CWE-444 | Host Header Injection & Cache Poisoning | `host.json`, `headers.json` | `HST001`-`HST003`, `HST002` | A01:2021 Broken Access Control / A05 Misconfiguration |
| 17 | CWE-639, CWE-284 | Insecure Direct Object References (IDOR) | `idor.json` | `IDR001`-`IDR003` | A01:2021 Broken Access Control |
| 18 | CWE-350, CWE-200 | Cloud Storage & Subdomain Takeover | `cloud.json`, `headers.json` | `CLD001`-`CLD003`, `CLD002` | A01:2021 Broken Access Control / A05 Misconfiguration |
| 19 | CWE-922, CWE-1021, CWE-345 | Client Storage & Reverse Tabnabbing | `client.json`, `headers.json` | `CLT001`-`CLT003`, `CLT002` | A04:2021 Insecure Design / A01 Broken Access Control |
| 20 | CWE-307, CWE-472, CWE-650, CWE-235 | Rate-Limiting & Parameter Tampering | `tamper.json`, `headers.json` | `TMP001`-`TMP005` | A04:2021 Insecure Design / A07 Auth Failures |
| — | CWE-362, CWE-840 | Concurrency Flaws & Business Logic | `logic.json` | `LGC001`-`LGC002` | A04:2021 Insecure Design |
| — | CWE-250, CWE-829 | Container Least Privilege & Base Images | `webfile.json` | `WEB004`-`WEB005` | A04:2021 Insecure Design / A06 Outdated |
| — | Multi-CWE | Enterprise Vulnerability Intelligence | `cve.json`, `headers.json` | `CVE001`-`CVE100` | A06:2021 Vulnerable and Outdated Components |
| **Total** | | **Comprehensive Web & API Defense** | **22 Documents** | **172 Rules** | **100% OWASP Coverage** |

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

`sentinel <url>` runs **all six categories in a single pass** — XSS, SQL injection,
headers & cookies, CORS & info leak, SSRF & redirects, and stack & shells — and prints a compact three-tier summary:

```bash
$ sentinel https://example.com
```

```text
URL : https://example.com

xss               : HARDENING NEEDED (missing CSP, missing X-Content-Type-Options,
                    inline script exposure)
sql injection     : SAFE (no indicators detected)
headers & cookies : HARDENING NEEDED (missing HSTS, missing X-Frame-Options,
                    missing X-Content-Type-Options, +4 more)
cors & info leak  : SAFE (no indicators detected)
ssrf & redirects  : SAFE (no indicators detected)
stack & shells    : SAFE (no indicators detected)
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
| `headers & cookies` | Insecure cookie flags (`HttpOnly`, `Secure`, `SameSite`), debug disclosure headers | Missing `HSTS`, `X-Frame-Options` (or CSP `frame-ancestors`), `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`; unkeyed cache without `Vary: Host`; `Server`/`X-Powered-By` banners |
| `cors & info leak` | Debug traceback in the body, `*` + `Allow-Credentials: true`, reflected origin + credentials | Wildcard `Access-Control-Allow-Origin: *` without credentials; takeover-prone cloud domain references (`CLD002`), unpinned `target=_blank` links (`CLT002`), client storage token leaks (`CLT001`) |
| `ssrf & redirects` | Directory listing (`Index of /`) or secret-file content served in the body | Same-origin link or form exposing a redirect/fetch parameter (`url`, `redirect`, `next`, `target`, `dest`, `return_to`, `callback`, …) |
| `stack & shells` | Debug traceback or exception dump in the response body (`traceback`, `werkzeug.debug`) | Disclosed backend framework banners (`X-Powered-By`, `X-AspNet-Version`, `X-Runtime`) |

A fully hardened target reports `SAFE` on every category:

```text
xss               : SAFE (no indicators detected)
sql injection     : SAFE (no indicators detected)
headers & cookies : SAFE (no indicators detected)
cors & info leak  : SAFE (no indicators detected)
ssrf & redirects  : SAFE (no indicators detected)
stack & shells    : SAFE (no indicators detected)
```

### Multi-page and markup inspection

By default, running `sentinel <url>` performs a full **deep audit** over up to **25 same-origin pages**
discovered from links and forms (`MAX_PAGES = 25`, `MAX_DISCOVERED_LINKS = 100`), with benign reflection
probing enabled automatically with zero flags:

```bash
sentinel https://example.com
```

```text
URL : https://example.com
pages : 3 inspected (same-origin)

xss               : HARDENING NEEDED (missing CSP, missing X-Content-Type-Options,
                    inline script exposure, +2 more)
...
```

To limit an audit to a single root page or disable reflection probing, pass `--no-deep` or `--no-probe`:

```bash
sentinel https://example.com --no-deep --no-probe
```

Markup checks run on every inspected page:

| Check | Category | Result |
|---|---|---|
| `<form method="post">` with no hidden `csrf`/`token`/`nonce`/`authenticity_token` field | `ssrf & redirects` | HARDENING NEEDED |
| External `<script src>` / stylesheet without `integrity=` (SRI) | `stack & shells` | HARDENING NEEDED |
| `http://` subresource or same-origin link on an HTTPS page (mixed content) | `stack & shells` | HARDENING NEEDED |
| `http://` form action on an HTTPS page | `headers & cookies` | HARDENING NEEDED |
| `<input type="password">` served over plain HTTP | `headers & cookies` | HARDENING NEEDED |
| `<input type="password">` without standard rate-limit headers (`TMP001`) | `headers & cookies` | HARDENING NEEDED |
| Sensitive `<input type="hidden">` fields (`role`, `is_admin`, `price`, `amount`) exposed to tampering (`TMP002`/`TMP005`) | `ssrf & redirects` | HARDENING NEEDED |
| Unvalidated client-side DOM XSS sinks (`innerHTML`, `document.write`, `eval`) in inline `<script>` (`DOM001`) | `xss` | HARDENING NEEDED |
| `window.addEventListener('message')` lacking origin verification (`DOM002`) | `xss` | HARDENING NEEDED |
| Dangling external links to takeover-prone cloud domains (`CLD002`) | `cors & info leak` | HARDENING NEEDED |
| External `target="_blank"` links lacking `rel="noopener noreferrer"` (`CLT002`) | `cors & info leak` | HARDENING NEEDED |
| Sensitive credentials/tokens in `localStorage` or `sessionStorage` (`CLT001`) | `cors & info leak` | HARDENING NEEDED |
| Disclosed server banners (`Server`, `X-Powered-By`, `X-Generator`) matching known CVEs (`cve.json`) | `stack & shells` | HARDENING NEEDED |
| Unauthenticated sensitive endpoints (`/.git/`, `/.env`, `/phpinfo.php`, `remote_agent.php`) | `stack & shells` | HARDENING NEEDED |
| Unvalidated file upload `<input type="file">` forms | `stack & shells` | HARDENING NEEDED |

### 4-Layer Deep Web Inspection Architecture

Sentinel's deep web inspection pipeline partitions passive web auditing into four distinct defensive layers:

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

### Reflection probing

Inert reflection probing is enabled by default during URL audits. When query parameters exist, benign
requests are sent using two inert markers:

* `sentinel_canary_<hex>` — purely alphanumeric, so it can never form markup, SQL
  syntax or a path traversal;
* `<sentinelprobe>` — inert angle brackets, the only way to distinguish an escaped
  echo from a raw one.

`xss` is only raised to `VULNERABLE` when `<sentinelprobe>` comes back **verbatim**. An
alphanumeric canary alone cannot prove missing encoding, because it survives HTML
escaping unchanged — so the markup marker, not the canary, is what confirms.

**Detail on demand:**

```bash
sentinel https://example.com --verbose          # full severity tables + remediation
sentinel https://example.com --format json      # machine-readable categories
```

### Scan guardrails

* **GET only.** No `POST`, `PUT`, `PATCH` or `DELETE` is ever issued, so no state mutates.
* **Same-origin only.** Link and form discovery keeps the exact scheme/host/port of the
  operator-supplied URL; external and protocol-relative links are discarded.
* **Hard caps.** At most 25 pages, 100 discovered links and 25 surface findings per scan,
  plus the `--timeout` on every request.
* **Identifiable.** A polite `User-Agent` (`sentinel-auditor/<version>`) is sent.
* **Inert markers.** Probing uses `<sentinelprobe>` and an alphanumeric canary only —
  never a SQLi, CMDi, XSS or template payload.

The explicit `sentinel audit-headers <url>` command keeps its detailed table output
unchanged; the compact view is only the default for the shorthand form.

### Website & Domain Whitelist

Sentinel provides a defensive allowlist mechanism that bypasses crawling and probing for designated local or internal targets and filters noise from trusted third-party destinations.

#### 1. Configuration (`src/json/whitelist.json`)

Default allowlisted hostnames and trusted external domains are configured in `src/json/whitelist.json`:

```json
{
  "domains": [
    "localhost",
    "127.0.0.1"
  ],
  "trusted_external_links": []
}
```

* **`domains`**: Hostnames or wildcard domain patterns (e.g. `localhost`, `127.0.0.1`, `*.example.internal`) that should be bypassed during live web audits.
* **`trusted_external_links`**: Hostnames or wildcards (e.g. `trusted-partner.com`, `*.github.com`) whose outbound `target="_blank"` links are considered approved and will not trigger reverse tabnabbing (`CLT002`) warnings.

#### 2. Local Allowlist (`.sentinelwhitelist`)

To customize allowlisted domains per repository without editing packaged files, place a `.sentinelwhitelist` file in your project root:

```text
# Local development and internal hosts
localhost
127.0.0.1
*.internal.corp
staging.local
```

Lines starting with `#` and empty lines are ignored.

#### 3. Whitelist Execution

When an allowlisted host is passed to Sentinel, scanning is bypassed immediately:

```bash
$ sentinel http://localhost
URL : http://localhost
status : WHITELISTED (domain matched allowlist)
```

The process exits with status code `0`.

### Static analysis (Zero-Flag & Shorthand)

```bash
$ sentinel src                                    # zero-flag SAST over directory
$ sentinel .                                      # zero-flag SAST over current directory
$ sentinel app.py                                 # zero-flag SAST over single file
$ sentinel audit-code ./src                       # explicit subcommand form
$ sentinel audit-code app.py --fail-on critical   # exits 2 if app.py is missing
$ sentinel audit-code . --exclude vendor --quiet
```

### Git Changed-Files Auditing

Quickly scan only modified, staged, or untracked files (.py, .js, .ts, .jsx, .tsx, .php, .html, .env, Dockerfile, docker-compose) in your git repository:

```bash
$ sentinel changed                                # shorthand for changed-files SAST
$ sentinel audit-code --changed                   # explicit flag form
$ sentinel changed --format sarif                 # SARIF export of changed files
```

### Pre-Commit Integration

Sentinel includes a native `.pre-commit-hooks.yaml` hook to guard git commits. Add Sentinel to your `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/Varethic/Sentinel
    rev: master
    hooks:
      - id: sentinel
```

This automatically runs `sentinel changed` on every commit with zero extra flags.

### Inline Suppression

Suppress intentional patterns or verified false positives directly in code using `# sentinel: ignore` or `# nosec`:

```python
cursor.execute(f"SELECT * FROM {table}")  # sentinel: ignore
raw_exec(command)  # nosec
```

Findings on lines bearing either comment (case-insensitive) are silently dropped before reporting.

### SARIF v2.1.0 & JSON output for CI/CD

Sentinel exports findings in standard **SARIF v2.1.0** (Static Analysis Results Interchange Format)
for seamless GitHub Code Scanning and VS Code SARIF Viewer integration:

```bash
# SARIF v2.1.0 export for GitHub Code Scanning
$ sentinel src --format sarif -o sentinel.sarif

# Standard JSON export
$ sentinel src --format json -o sentinel.json --fail-on high
```

Sample JSON report:

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

Sentinel includes a ready-to-use CI workflow at `.github/workflows/sentinel.yml`:

```yaml
name: Sentinel Security Gate

on:
  push:
    branches: [ master, main ]
  pull_request:
    branches: [ master, main ]

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
        run: |
          python -m pip install --upgrade pip
          pip install -e .

      - name: Validate Rule Documents
        run: |
          sentinel rules

      - name: Run Sentinel SAST (SARIF export)
        run: |
          sentinel audit-code src --format sarif -o results.sarif --fail-on high

      - name: Upload SARIF report
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif
```

### Commands reference

| Command | Purpose |
|---|---|
| `sentinel <target>` | Shorthand zero-flag audit: URL for web surface scan, or path for SAST. |
| `sentinel changed` | Audit only modified and newly added git files. |
| `sentinel audit-code <path>` | Static analysis across Python, web, and container files (all 172 rules across 22 documents). |
| `sentinel audit-headers <url>` | Deep passive HTTP header, cookie, and markup audit. |
| `sentinel rules [--show]` | Validate and list every loaded rule document with CWE, CVE, and date. |

Common options: `--format cli|json|sarif`, `--output FILE`, `--fail-on none|low|medium|high|critical`,
`--no-color`. The URL commands add `--timeout SECONDS`, `--no-redirects`, `--deep/--no-deep`
(inspect up to 25 same-origin pages), `--probe/--no-probe` (inert reflection markers) and
`--verbose` (every reason, plus the inspected URLs). `audit-code` adds `--changed` / `-c`,
`--exclude DIR` (repeatable) and `--quiet`.

---

## Authorized Security Sandboxes & Test Targets (50 URLs)

Sentinel's passive URL inspection engine can be safely tested against curated, publicly accessible security sandboxes and intentional testbeds. Because Sentinel issues strictly read-only HTTP `GET` requests and benign reflection markers, testing against these authorized domains produces zero malicious traffic and modifies no remote server state.

### Automated PowerShell Batch Verification

Run the zero-flag `sentinel <url>` command across test targets in PowerShell:

```powershell
# Curated list of authorized sandbox targets
$targets = @(
    # Google Firing Range
    "https://public-firing-range.appspot.com/reflected/index.html",
    "https://public-firing-range.appspot.com/reflected/parameter/body?q=test",
    "https://public-firing-range.appspot.com/reflected/parameter/attribute_unquoted?q=test",
    "https://public-firing-range.appspot.com/reflected/parameter/attribute_quoted?q=test",
    "https://public-firing-range.appspot.com/reflected/parameter/script?q=test",
    "https://public-firing-range.appspot.com/dom/index.html",
    "https://public-firing-range.appspot.com/dom/toxicdom/location/hash/innerHtml",
    "https://public-firing-range.appspot.com/dom/toxicdom/location/search/documentWrite",
    "https://public-firing-range.appspot.com/dom/toxicdom/postMessage/eval",
    "https://public-firing-range.appspot.com/redirect/index.html",
    "https://public-firing-range.appspot.com/redirect/parameter?url=https://example.com",
    "https://public-firing-range.appspot.com/cors/index.html",
    "https://public-firing-range.appspot.com/escape/index.html",
    "https://public-firing-range.appspot.com/tags/index.html",
    "https://public-firing-range.appspot.com/urldom/index.html",
    # Acunetix / Vulnweb
    "http://testphp.vulnweb.com/",
    "http://testphp.vulnweb.com/login.php",
    "http://testphp.vulnweb.com/search.php?test=query",
    "http://testphp.vulnweb.com/artists.php?artist=1",
    "http://testphp.vulnweb.com/categories.php",
    "http://testaspnet.vulnweb.com/",
    "http://testaspnet.vulnweb.com/Default.aspx",
    "http://testasp.vulnweb.com/",
    "http://testhtml5.vulnweb.com/",
    "http://rest.vulnweb.com/",
    # PortSwigger & BadSSL
    "https://portswigger.net/web-security",
    "https://badssl.com/",
    "https://mixed-script.badssl.com/",
    "https://mixed.badssl.com/",
    "https://mixed-form.badssl.com/",
    "https://http.badssl.com/",
    "https://hsts.badssl.com/",
    "https://upgrade.badssl.com/",
    # OWASP & Vulnerable Demo Apps
    "https://demo.owasp-juice.shop/",
    "https://juice-shop.herokuapp.com/",
    "http://demo.testfire.net/",
    "http://demo.testfire.net/login.jsp",
    "http://demo.testfire.net/search.jsp?query=test",
    "http://zero.webappsecurity.com/",
    "http://zero.webappsecurity.com/login.html",
    "https://ginandjuice.shop/",
    "https://ginandjuice.shop/catalog",
    "https://ginandjuice.shop/login",
    # HTTP & Reference Endpoints
    "https://example.com",
    "https://www.iana.org/domains/reserved",
    "https://httpbin.org/",
    "https://httpbin.org/headers",
    "https://httpbin.org/cookies/set/session/test123",
    "https://httpbin.org/response-headers?X-Powered-By=PHP/7.3.10",
    "http://localhost"
)

# Automated batch execution loop
$targets | ForEach-Object {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "[*] Auditing: $_" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    sentinel $_
}
```

PowerShell one-liner shorthand:
```powershell
$targets | ForEach-Object { Write-Host "`n[*] Auditing: $_" -ForegroundColor Cyan; sentinel $_ }
```

### 1. Google Firing Range (Reflected XSS, DOM XSS, Redirects, CORS)
- `https://public-firing-range.appspot.com/reflected/index.html`
- `https://public-firing-range.appspot.com/reflected/parameter/body?q=test`
- `https://public-firing-range.appspot.com/reflected/parameter/attribute_unquoted?q=test`
- `https://public-firing-range.appspot.com/reflected/parameter/attribute_quoted?q=test`
- `https://public-firing-range.appspot.com/reflected/parameter/script?q=test`
- `https://public-firing-range.appspot.com/dom/index.html`
- `https://public-firing-range.appspot.com/dom/toxicdom/location/hash/innerHtml`
- `https://public-firing-range.appspot.com/dom/toxicdom/location/search/documentWrite`
- `https://public-firing-range.appspot.com/dom/toxicdom/postMessage/eval`
- `https://public-firing-range.appspot.com/redirect/index.html`
- `https://public-firing-range.appspot.com/redirect/parameter?url=https://example.com`
- `https://public-firing-range.appspot.com/cors/index.html`
- `https://public-firing-range.appspot.com/escape/index.html`
- `https://public-firing-range.appspot.com/tags/index.html`
- `https://public-firing-range.appspot.com/urldom/index.html`

### 2. Acunetix / Vulnweb Official Test Sites (Forms, Stack Banners, Classic Web Surface)
- `http://testphp.vulnweb.com/`
- `http://testphp.vulnweb.com/login.php`
- `http://testphp.vulnweb.com/search.php?test=query`
- `http://testphp.vulnweb.com/artists.php?artist=1`
- `http://testphp.vulnweb.com/categories.php`
- `http://testaspnet.vulnweb.com/`
- `http://testaspnet.vulnweb.com/Default.aspx`
- `http://testasp.vulnweb.com/`
- `http://testhtml5.vulnweb.com/`
- `http://rest.vulnweb.com/`

### 3. PortSwigger & BadSSL (Transport, Mixed Content, TLS, Security Headers)
- `https://portswigger.net/web-security`
- `https://badssl.com/`
- `https://mixed-script.badssl.com/`
- `https://mixed.badssl.com/`
- `https://mixed-form.badssl.com/`
- `https://http.badssl.com/`
- `https://hsts.badssl.com/`
- `https://upgrade.badssl.com/`

### 4. OWASP & Authorized Vulnerable Demo Apps (SPA, API, Cookies, CSP)
- `https://demo.owasp-juice.shop/`
- `https://juice-shop.herokuapp.com/`
- `http://demo.testfire.net/`
- `http://demo.testfire.net/login.jsp`
- `http://demo.testfire.net/search.jsp?query=test`
- `http://zero.webappsecurity.com/`
- `http://zero.webappsecurity.com/login.html`
- `https://ginandjuice.shop/`
- `https://ginandjuice.shop/catalog`
- `https://ginandjuice.shop/login`

### 5. HTTP & Header Reference Endpoints (Headers, Cookies, Version Banners, Whitelist)
- `https://example.com`
- `https://www.iana.org/domains/reserved`
- `https://httpbin.org/`
- `https://httpbin.org/headers`
- `https://httpbin.org/cookies/set/session/test123`
- `https://httpbin.org/response-headers?X-Powered-By=PHP/7.3.10`
- `http://localhost`

---

## Safety model

* Static analysis **parses** source with `ast`; it never imports, executes, or evaluates it.
* URL auditing sends ordinary `GET` requests only. No payloads, no fuzzing, no brute force,
  and **no `POST`/`PUT`/`PATCH`/`DELETE`** — no state on the target is ever modified.
* By default one audit crawl inspects up to **25 same-origin** pages (`MAX_PAGES = 25`, `MAX_DISCOVERED_LINKS = 100`), with a hard cap on discovered links and the `--timeout` applied to every request.
* Discovered links and form actions are followed **only** when they match the exact
  scheme, host and port of the URL you supplied.
* The reflection probe is inert text (`<sentinelprobe>`) placed only in a query parameter
  the operator already supplied; it contains no script, quote, or SQL metacharacter, and
  is enabled by default during URL audits (toggle with `--no-probe`).
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
* Header auditing crawls up to 25 same-origin pages by default; it does not execute
  JavaScript and will not see headers added client-side. Pass `--no-deep` for a single-page check.
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
