# Changelog

All notable changes to the Sentinel project are documented in this file.

## [1.3] - 2026-11-16

### Authenticated Scanning & Credential Support
- **Multi-Authentication Probing**: Added `--bearer <token>`, `-H`/`--header "Key: Value"`, and `-b`/`--cookie "k=v"` CLI flags.
- **Session Forwarding**: Authenticated sessions and custom headers are automatically propagated across passive header audits (`headers.py`) and active assessment probes (`sqli.py` and `scan.py`).

### Automated Vulnerability Remediation & Patching
- **Auto-Fixer (`src/patch.py`)**: Introduced `sentinel fix <target>` to safely generate Git-compatible unified diffs and patch vulnerable code.
- **Rule Fix Templates**: Implemented automated remediations for `CMDI002` (`shell=False`), `AUTH001` (`verify=True`), `AUTH003` (`debug=False`), `XSS003` (`autoescape=True`), `API001` (`introspection=False`), and `SECR003` (`secrets` module migration).
- **In-Place Patching (`--write`)**: Supports previewing dry-run diffs or applying safe fixes directly with `--write`.

### CI/CD Security Gate & DevSecOps Integration
- **Non-Interactive CI Gate (`sentinel ci`)**: Added dedicated `sentinel ci <target>` command running in headless, non-interactive mode.
- **Configurable Severity Thresholds (`--fail-on`)**: Exits with code `1` when findings meet or exceed the threshold (`low`, `medium`, `high`, `critical`), or `0` when clean.
- **Dual Target CI Auditing**: Seamlessly runs SAST audits on source trees and active/passive verification on URLs.
- **SARIF & JSON Export**: Added `--sarif <file>` and `--json <file>` flags for direct ingestion into GitHub Code Scanning and DevSecOps pipelines.
- **GitHub Actions Workflow**: Updated `.github/workflows/sentinel.yml` for automated CI pull-request analysis and SARIF upload.

## [1.2] - 2026-11-14

### CLI Experience & Terminal Flow
- **Auto Terminal Clearing on Enter**: Terminal is now automatically cleared immediately upon pressing Enter after a scan, providing a fresh screen for the next domain input.
- **Wiped Terminal Before Results Display**: Replaced inline clutter with a clean screen transition directly into the centered vulnerability report and remediation panel.
- **Seamless Target Handoff**: If a target domain is supplied via CLI arguments, Sentinel runs the audit, displays results, and seamlessly offers to scan additional targets in the clean interactive loop.
- **Graceful Termination**: Typing `exit`, `quit`, or pressing `Ctrl+C` clears the terminal and terminates cleanly.

## [1.1] - 2026-11-14

### Security & Bug Fixes
1. **Fixed ReDoS in Header Discovery (`src/active/scan.py`)**: Replaced exponential backtracking nested quantifier `r"/labs/[a-z0-9-]+(?:/[a-z0-9-]+)*"` with linear pattern `r"/labs/[a-z0-9/_-]+"`.
2. **Fixed ReDoS in API Surface Check (`src/active/scan.py`)**: Replaced backtracking regex `r"/[a-z0-9-]+(?:/[a-z0-9-]+)*/api/[a-z0-9/_-]+"` with linear `r"/[a-z0-9/_-]+/api/[a-z0-9/_-]+"`.
3. **Fixed ReDoS in BOLA Detection (`src/active/scan.py`)**: Replaced backtracking pattern `r"/[a-z0-9-]+(?:/[a-z0-9-]+)*/api/[a-z0-9/_{}-]+"` with safe `r"/[a-z0-9/_-]+/api/[a-z0-9/_{}-]+"`.
4. **Fixed ReDoS in Hidden Path Recon (`src/active/scan.py`)**: Replaced nested quantifier pattern `r"/[a-z0-9._-]+(?:/[a-z0-9._-]+)*/?"` with linear pattern `r"/[a-z0-9._/-]+"`.
5. **Eliminated Insecure Command Execution (`src/run.py`)**: Replaced raw `os.system("cls" if os.name == "nt" else "clear")` with cross-platform `console.clear()`.
6. **Fixed Playwright Browser Resource Leak (`src/active/render.py`)**: Enclosed Chromium page rendering and lifecycle in a `try...finally: browser.close()` block to guarantee process cleanup on timeouts.
7. **Optimized SPA Detection (`src/active/render.py`)**: Removed aggressive fallback triggering that launched Chromium on every page lacking a `<form>` tag; restricted SPA rendering to verified SPA markers (`__NEXT_DATA__`, `id="root"`, etc.).
8. **Integrated Passive Header Audit into Report (`src/run.py`)**: Integrated `blue_result` findings from `headers_analyzer._audit_web` into the report table so passive header and cookie findings are surfaced.
9. **Fixed SQLi AST Variable Tracking Scope (`src/analyzers/sqli.py`)**: Scoped variable assignments within function visitors (`visit_FunctionDef`, `visit_AsyncFunctionDef`) to prevent variable leakage across different functions.
10. **Removed Inline Dynamic Imports (`src/active/scan.py`)**: Replaced repeated `__import__("urllib.parse")` calls with standard module-level imports.

### Features & Architecture
11. **Actionable Remediation & Defense Guidance (`src/run.py`)**: Added dedicated remediation guidance panel citing official OWASP Top 10 (2021/2023) and CWE identifiers with concrete technical fixes and defense strategies.
12. **Centralized Configuration (`Config` class)**: Removed fragmented global variables; consolidated categories, timeouts, budgets, markers, and remedies into central `Config` classes.
13. **Interactive Single-Command CLI (`src/run.py`, `src/cli.py`)**: Running `sentinel` without arguments launches an interactive loop prompting for target domain/URL and allowing continuous audits via Enter.
14. **CLI Flags (`--version` & `--info`)**: Added clean `--version` and `--info` flags with defensive scope notices and educational disclaimers.
15. **Strict Cybersecurity License (`LICENSE`)**: Updated licensing terms to strictly mandate authorized, defensive, and educational auditing while prohibiting unauthorized offensive attacks.
