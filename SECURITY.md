# Security Policy

## Supported versions

Sentinel is pre-1.0 software. Security fixes are applied to the latest release only.

| Version | Supported |
|---|---|
| `0.1.x` | Yes |
| `< 0.1` | No |

## Authorized use and non-destructive security policy

Sentinel is a **defensive** security tool. It is designed to help operators find
weaknesses in code and configuration they are already responsible for. It has no
offensive capability and is explicitly not an exploitation framework.

### What Sentinel does

* **Static analysis (`sentinel audit-code`)** parses Python source with the standard
  library `ast` module. Source files are read as text and inspected as syntax trees.
  They are **never imported, executed, compiled or evaluated**, so analysing a
  malicious file cannot run its code in the auditor process.
* **URL auditing (`sentinel <url>`)** sends ordinary `GET` requests and inspects the
  responses. It reads status codes, response headers, cookies and response bodies.
* **Reflection probing (`--probe`)** is opt-in. It places inert marker text
  (`<sentinelprobe>` and an alphanumeric `sentinel_canary_*` value) into a query
  parameter the operator already supplied, and checks whether the value comes back
  unescaped.

### What Sentinel never does

* No **`POST`, `PUT`, `PATCH` or `DELETE`** requests over the network — every HTTP
  request is a `GET`, so no state on the target is created, modified or deleted.
* No **exploitation payloads** — no SQL injection strings, no command injection, no
  deserialization gadgets, no template injection expressions, no exploit chains.
* No **brute force, credential guessing, fuzzing, request replay or load generation**.
* No **crawling beyond the configured limit** — link discovery follows at most five
  same-origin pages (`--deep`), with a hard cap on discovered links.
* No **cross-origin requests** — discovered links and form actions are followed only
  when they share the exact scheme, host and port of the URL you supplied.
* No **server-side or destructive behaviour** — no `eval`, no shell invocation on
  target data, no file writes derived from responses.
* No **telemetry** — nothing is sent anywhere except the URL you explicitly pass.

### Authorized use only

Run Sentinel only against:

* code you own or maintain, or code you have explicit written permission to review;
* systems you own or operate, or targets covered by a scope agreement or bug bounty
  program that authorises this class of automated testing.

Because URL auditing makes real network requests to the target you name, the requests
originate from your machine and are attributable to you. **You are responsible for
ensuring you have authorisation** before pointing Sentinel at any host. Do not use it
against third-party systems without permission.

If you are unsure whether a target is in scope, do not scan it.

### Interpreting results

Sentinel is a fast, low-noise first gate, not a substitute for a full security review.
The three-tier verdicts deliberately separate what was *observed* from what is merely
*missing hardening*:

* `VULNERABLE` — a confirming signal was directly observed (for example unescaped
  reflection, a database error in the body, or insecure cookie flags).
* `HARDENING NEEDED` — a control is absent or weak. Real and worth fixing, but not
  proof of exploitability.
* `SAFE` — no confirming signal and no missing control for that category.

A `SAFE` verdict means Sentinel found no indicators; it does not certify the absence of
vulnerabilities.

## Reporting a vulnerability in Sentinel itself

If you find a security issue **in Sentinel** — for example a crafted input file that
crashes or hangs the parser, a path traversal in file discovery, a way to make the
auditor send a request to an unintended host, or a dependency vulnerability — please
report it responsibly.

**Please do not open a public issue for a security vulnerability.**

Report privately through either channel:

1. **GitHub Security Advisories (preferred)** — go to the repository's **Security** tab
   and select **Report a vulnerability**. This opens a private advisory visible only to
   the maintainers.
2. **Email** — contact the maintainer listed on the
   [Varethic GitHub profile](https://github.com/Varethic) if advisories are unavailable.

Please include:

* the Sentinel version (`sentinel --version`) and your Python version;
* the affected component (analyzer name, rule ID, CLI command);
* a minimal reproduction — a short source snippet or the smallest command line that
  triggers the issue;
* the observed behaviour and the impact you believe it has.

### What to expect

* Acknowledgement of your report, typically within a few days.
* An assessment and, where confirmed, a fix in the next release.
* Credit in the advisory once a fix ships, if you would like to be named.

Please give us a reasonable window to release a fix before any public disclosure.

### Out of scope

The following are **not** considered vulnerabilities in Sentinel:

* false positives or false negatives in detection quality — please open a regular issue
  with a sample that reproduces it;
* missing detection for a specific framework or a rule you would like added — that is a
  feature request;
* findings Sentinel reports about **your own** target — those describe the target, not
  a flaw in Sentinel;
* reports from automated scanners unaccompanied by an explanation of the issue.

## Dependencies

Sentinel depends on `typer`, `rich`, `pydantic` and `httpx`. Vulnerabilities in those
libraries should be reported to their respective maintainers; if Sentinel's usage
amplifies the impact, we still want to hear about it.
