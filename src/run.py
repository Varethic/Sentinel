from __future__ import annotations
import concurrent.futures, json, sys, time, urllib.parse
from pathlib import Path
from rich.align import Align
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from src.active import scan as active_scan
from src.analyzers import (
    api as api_analyzer,
    auth as auth_analyzer,
    client as client_analyzer,
    cloud as cloud_analyzer,
    cmdi as cmdi_analyzer,
    cve as cve_analyzer,
    deps as deps_analyzer,
    deserial as deserial_analyzer,
    headers as headers_analyzer,
    host as host_analyzer,
    idor as idor_analyzer,
    logic as logic_analyzer,
    redos as redos_analyzer,
    secrets as secrets_analyzer,
    sqli as sqli_analyzer,
    ssrf as ssrf_analyzer,
    ssti as ssti_analyzer,
    tamper as tamper_analyzer,
    traversal as traversal_analyzer,
    webfile as webfile_analyzer,
    xss as xss_analyzer,
    xxe as xxe_analyzer,
)
from src import hook, openapi, sca
from src.core import engine
from src.core.loader import Severity, _load_all
from src.patch import _fix
from src.reporters import json as json_rep, sarif as sarif_rep

_CONSOLE = Console()

class Config:
    def _version(self) -> str:
        return "1.4"

    def _info(self) -> str:
        return (
            "Sentinel v1.3 - Defensive Security Auditor & DevSecOps Gate\n"
            "Preliminary security assessment and defensive educational research only.\n"
            "Strictly prohibited: unauthorized scanning, malicious attacks, or exploitation."
        )

    def _banner(self) -> str:
        return (
            f"[bold green]Sentinel Defensive Security Auditor[/bold green] v{self._version()}\n"
            "[dim]Preliminary audit & educational defense. Prohibits unauthorized attacks.[/dim]"
        )

    def _schemes(self) -> tuple[str, ...]:
        return ("http://", "https://")

    def _timeout(self) -> float:
        return 10.0

    def _delay(self) -> float:
        return 0.05

    def _budget(self) -> int:
        return 3000

    def _categories(self) -> list[tuple[str, str]]:
        return [
            ("SQL Injection", "SQLi"),
            ("Cross-Site Scripting (XSS)", "XSS (reflected)"),
            ("Command Injection", "CMDi"),
            ("Path Traversal (LFI)", "LFI"),
            ("Server-Side Template Injection", "SSTI"),
            ("XML External Entity", "XXE"),
            ("Server-Side Request Forgery", "SSRF"),
            ("Header Spoofing", "Header Spoofing"),
            ("CORS Misconfiguration", "CORS Misconfiguration"),
            ("JWT Broken Verification", "JWT (broken verification)"),
            ("Mass Assignment", "Mass Assignment"),
            ("API Exposure / BOLA", "API Exposure / BOLA"),
            ("Insecure Deserialization", "Insecure Deserialization"),
            ("DOM XSS", "DOM XSS (source->sink)"),
            ("Open Redirect", "Open Redirect"),
            ("Info Disclosure", "Info Disclosure (hidden path)"),
            ("Weak PRNG Token", "Weak PRNG Token"),
            ("HTTP Security Headers", "headers"),
        ]

    def _remediation(self) -> dict[str, dict[str, str]]:
        return {
            "SQL Injection": {
                "ref": "CWE-89 / OWASP A03:2021",
                "fix": "Use Prepared Statements; never concatenate input into query string.",
                "def": "Enforce Database Least Privilege and adopt ORMs with automated escaping.",
            },
            "Cross-Site Scripting (XSS)": {
                "ref": "CWE-79 / OWASP A03:2021",
                "fix": "Apply Context-aware Output Encoding on reflected user parameters.",
                "def": "Implement a strict Content Security Policy and set HttpOnly on cookies.",
            },
            "Command Injection": {
                "ref": "CWE-78 / OWASP A03:2021",
                "fix": "Avoid system shell calls; pass argument lists to subprocess(shell=False).",
                "def": "Validate inputs with strict allowlist; run workers with low privilege.",
            },
            "Path Traversal (LFI)": {
                "ref": "CWE-22 / OWASP A01:2021",
                "fix": "Resolve canonical paths and verify files stay inside authorized directory.",
                "def": "Map client file parameters to internal IDs instead of raw filenames.",
            },
            "Server-Side Template Injection": {
                "ref": "CWE-1336 / OWASP A03:2021",
                "fix": "Pass data via template context variables rather than embedding in syntax.",
                "def": "Enable template sandbox environments and forbid arbitrary callables.",
            },
            "XML External Entity": {
                "ref": "CWE-611 / OWASP A05:2021",
                "fix": "Disable external entity resolution (DTD) in XML parsers.",
                "def": "Migrate to safer serialization formats like JSON or Protocol Buffers.",
            },
            "Server-Side Request Forgery": {
                "ref": "CWE-918 / OWASP A10:2021",
                "fix": "Validate destination URLs and block private/link-local IP addresses.",
                "def": "Enforce strict egress network firewall policies and isolate proxy workers.",
            },
            "Header Spoofing": {
                "ref": "CWE-345 / OWASP A07:2021",
                "fix": "Trust forwarding headers (X-Forwarded-For) only from internal proxies.",
                "def": "Sanitize and strip untrusted upstream headers at edge reverse proxies.",
            },
            "CORS Misconfiguration": {
                "ref": "CWE-942 / OWASP A01:2021",
                "fix": "Never reflect arbitrary Origin headers with Allow-Credentials: true.",
                "def": "Allowlist trusted origins; reject wildcards on authenticated routes.",
            },
            "JWT Broken Verification": {
                "ref": "CWE-345 / OWASP A07:2021",
                "fix": "Strictly verify signatures and enforce explicit algorithm allowlists.",
                "def": "Reject 'none' algorithm and enforce adequate cryptographic key length.",
            },
            "Mass Assignment": {
                "ref": "CWE-915 / OWASP API6:2023",
                "fix": "Bind incoming requests to explicit DTOs rather than unpacking into models.",
                "def": "Allowlist permitted fields and reject administrative fields in client.",
            },
            "API Exposure / BOLA": {
                "ref": "CWE-284 / OWASP API1:2023",
                "fix": "Enforce Object-Level Access Control checking caller permission per ID.",
                "def": "Use non-sequential UUIDs and enforce authorization middleware on routes.",
            },
            "Insecure Deserialization": {
                "ref": "CWE-502 / OWASP A08:2021",
                "fix": "Never deserialize untrusted payloads with execution-capable parsers.",
                "def": "Use pure-data formats like JSON with HMAC signatures to verify integrity.",
            },
            "DOM XSS": {
                "ref": "CWE-79 / OWASP A03:2021",
                "fix": "Avoid passing URL or hash data to execution sinks (innerHTML, write).",
                "def": "Use safe DOM APIs like textContent or sanitize using DOMPurify.",
            },
            "Open Redirect": {
                "ref": "CWE-601 / OWASP A01:2021",
                "fix": "Validate redirect destinations against internal relative path allowlist.",
                "def": "Avoid accepting raw URLs as parameters; notify users when leaving site.",
            },
            "Info Disclosure": {
                "ref": "CWE-200 / OWASP A05:2021",
                "fix": "Disable directory listing, verbose error stack traces, and debug pages.",
                "def": "Block access to sensitive paths (.git, .env, /admin) via web server.",
            },
            "Weak PRNG Token": {
                "ref": "CWE-330 / OWASP A02:2021",
                "fix": "Use cryptographically secure pseudorandom generators (secrets module).",
                "def": "Ensure token entropy is at least 128 bits and implement short expiration.",
            },
            "HTTP Security Headers": {
                "ref": "CWE-693 / OWASP A05:2021",
                "fix": "Configure Content-Security-Policy, HSTS, and X-Content-Type-Options.",
                "def": "Ensure all cookies include Secure, HttpOnly, and SameSite attributes.",
            },
        }

def _sast_analyzers() -> list:
    return [
        sqli_analyzer,
        xss_analyzer,
        cmdi_analyzer,
        traversal_analyzer,
        secrets_analyzer,
        ssrf_analyzer,
        deserial_analyzer,
        xxe_analyzer,
        ssti_analyzer,
        auth_analyzer,
        redos_analyzer,
        api_analyzer,
        deps_analyzer,
        host_analyzer,
        idor_analyzer,
        cloud_analyzer,
        client_analyzer,
        tamper_analyzer,
        logic_analyzer,
        cve_analyzer,
        webfile_analyzer,
    ]

def _parse_auth(args: list[str]) -> tuple[dict[str, str], dict[str, str]]:
    headers: dict[str, str] = {}
    cookies: dict[str, str] = {}
    idx = 0
    while idx < len(args):
        arg = args[idx]
        if arg == "--bearer" and idx + 1 < len(args):
            headers["Authorization"] = f"Bearer {args[idx + 1]}"
            idx += 2
            continue
        if arg in ("--header", "-H") and idx + 1 < len(args):
            raw = args[idx + 1]
            if ":" in raw:
                k, v = raw.split(":", 1)
                headers[k.strip()] = v.strip()
            idx += 2
            continue
        if arg in ("--cookie", "-b") and idx + 1 < len(args):
            raw = args[idx + 1]
            for part in raw.split(";"):
                if "=" in part:
                    ck, cv = part.split("=", 1)
                    cookies[ck.strip()] = cv.strip()
            idx += 2
            continue
        idx += 1
    return headers, cookies

def _severity_rank(sev: Severity | str) -> int:
    val = (sev.value if isinstance(sev, Severity) else str(sev)).upper()
    return {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}.get(val, 0)

class Auditor:
    def __init__(self) -> None:
        self.cfg = Config()
        self.console = _CONSOLE

    def _clean(self) -> None:
        self.console.clear()

    def _host(self, url: str) -> str:
        parsed = urllib.parse.urlparse(url)
        return parsed.netloc or parsed.path or url

    def _blue(
        self,
        url: str,
        timeout: float,
        headers: dict[str, str] | None = None,
        cookies: dict[str, str] | None = None,
    ):
        try:
            return headers_analyzer._audit_web(
                url,
                timeout=timeout,
                follow_redirects=True,
                probe=True,
                deep=True,
                headers=headers,
                cookies=cookies,
            )
        except Exception as exc:
            return exc

    def _red(
        self,
        url: str,
        budget: int,
        delay: float,
        timeout: float,
        headers: dict[str, str] | None = None,
        cookies: dict[str, str] | None = None,
    ):
        try:
            return active_scan._run(
                url,
                crawl=True,
                budget=budget,
                delay=delay,
                timeout=timeout,
                max_pages=60,
                headers=headers,
                cookies=cookies,
            )
        except Exception as exc:
            return exc

    def _status(self, finding) -> str:
        evidence = (getattr(finding, "evidence", "") or "").lower()
        category = (getattr(finding, "category", "") or "").lower()
        if "flag" in evidence or "bypass" in category:
            return "Critical"
        return "Medium"

    def _advice(self, matched_categories: list[str]) -> Panel | None:
        if not matched_categories:
            return None
        remediations = self.cfg._remediation()
        content = []
        for cat in matched_categories:
            info = remediations.get(cat)
            if not info:
                continue
            content.append(f"[bold cyan]{cat}[/bold cyan] ([dim]{info['ref']}[/dim])")
            content.append(f"  • [yellow]Fix:[/yellow] {info['fix']}")
            content.append(f"  • [green]Defense:[/green] {info['def']}\n")
        if not content:
            return None
        return Panel(
            "\n".join(content).rstrip(),
            title="[bold yellow]Remediation Guidance & Defensive Best Practices[/bold yellow]",
            border_style="yellow",
        )

    def _table(self, url: str, blue, red) -> tuple[Table, list[str]]:
        table = Table(
            title=f"Url Target : {self._host(url)}",
            show_header=True,
            header_style="bold",
        )
        table.add_column("Vulnerability", style="cyan", no_wrap=True)
        table.add_column("Status", justify="center", no_wrap=True)
        table.add_column("Endpoint", overflow="fold")

        red_findings = []
        if not isinstance(red, Exception):
            red_findings = list(getattr(red, "findings", []) or [])

        red_by_cat: dict[str, list] = {}
        for f in red_findings:
            red_by_cat.setdefault(getattr(f, "category", ""), []).append(f)

        blue_findings = []
        if not isinstance(blue, Exception):
            blue_findings = list(getattr(blue, "findings", []) or [])

        flagged_categories: list[str] = []

        for display_name, cat_key in self.cfg._categories():
            if cat_key == "headers":
                if blue_findings:
                    flagged_categories.append(display_name)
                    missing_desc = ", ".join(f.rule_name for f in blue_findings[:3])
                    table.add_row(display_name, "[yellow]Medium[/yellow]", missing_desc)
                else:
                    table.add_row(display_name, "[green]Pass[/green]", "-")
                continue

            matched = red_by_cat.get(cat_key, [])
            if matched:
                flagged_categories.append(display_name)
                status = self._status(matched[0])
                style = "red" if status == "Critical" else "yellow"
                seen = set()
                for f in matched:
                    ep = str(getattr(f, "target", ""))
                    if ep in seen:
                        continue
                    seen.add(ep)
                    if len(seen) > 2:
                        break
                    table.add_row(display_name, f"[{style}]{status}[/{style}]", ep)
                if len(seen) == 0:
                    table.add_row(display_name, f"[{style}]{status}[/{style}]", "-")
            else:
                table.add_row(display_name, "[green]Pass[/green]", "-")

        return table, flagged_categories

    def _scan(
        self,
        url: str,
        headers: dict[str, str] | None = None,
        cookies: dict[str, str] | None = None,
    ) -> tuple:
        progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            console=self.console,
        )
        t_blue = progress.add_task("blue team (passive audit)", total=1)
        t_red = progress.add_task("red team (active payloads)", total=1)

        term_height = self.console.size.height or 24
        blue_result = None
        red_result = None
        with (
            Live(
                Align.center(progress, vertical="middle", height=term_height),
                console=self.console,
                refresh_per_second=10,
                transient=True,
            ),
            concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool,
        ):
            bf = pool.submit(self._blue, url, self.cfg._timeout() * 2, headers, cookies)
            rf = pool.submit(
                self._red,
                url,
                self.cfg._budget(),
                self.cfg._delay(),
                self.cfg._timeout(),
                headers,
                cookies,
            )
            while not (bf.done() and rf.done()):
                if bf.done():
                    progress.update(t_blue, completed=1)
                if rf.done():
                    progress.update(t_red, completed=1)
                time.sleep(0.2)
            blue_result = bf.result()
            red_result = rf.result()
            progress.update(t_blue, completed=1)
            progress.update(t_red, completed=1)
            time.sleep(0.2)

        return blue_result, red_result

    def _show(self, url: str, blue, red) -> None:
        self._clean()
        table, flagged = self._table(url, blue, red)
        self.console.print()
        self.console.print(Align.center(table))
        advice = self._advice(flagged)
        if advice is not None:
            self.console.print()
            self.console.print(advice)

    def _wait(self) -> bool:
        try:
            self.console.print()
            msg = "[bold cyan]Press Enter to scan next target (or 'exit' to quit): [/bold cyan]"
            raw = self.console.input(msg).strip()
            return raw.lower() not in ("exit", "quit", "q")
        except (KeyboardInterrupt, EOFError):
            return False

    def _prompt(self) -> str | None:
        try:
            self.console.print()
            msg = "[bold green]Enter target domain or URL (or 'exit' to quit): [/bold green]"
            target = self.console.input(msg).strip()
            if not target or target.lower() in ("exit", "quit", "q"):
                return None
            if not target.startswith(self.cfg._schemes()):
                target = "http://" + target
            return target
        except (KeyboardInterrupt, EOFError):
            return None

    def _loop(
        self,
        initial: str | None = None,
        headers: dict[str, str] | None = None,
        cookies: dict[str, str] | None = None,
    ) -> None:
        target = initial
        while True:
            if not target:
                self._clean()
                self.console.print(Panel(self.cfg._banner(), border_style="green"))
                target = self._prompt()
                if not target:
                    break
            self._clean()
            blue, red = self._scan(target, headers=headers, cookies=cookies)
            self._show(target, blue, red)
            target = None
            if not self._wait():
                break
            self._clean()
        self._clean()
        self.console.print("[dim]Sentinel terminated. Stay safe![/dim]")

    def _run_sast_ci(
        self,
        target_path: Path,
        threshold: str,
        sarif_file: Path | None = None,
        json_file: Path | None = None,
    ) -> int:
        print(f"Sentinel CI (SAST): Auditing code at {target_path}...")
        report = engine._run_analyzers(target_path, _sast_analyzers())
        thresh_rank = _severity_rank(threshold)
        blocking = [f for f in report.findings if _severity_rank(f.severity) >= thresh_rank]

        for f in report.findings:
            sev = f.severity.value.upper()
            status = "BLOCKING" if _severity_rank(f.severity) >= thresh_rank else "ADVISORY"
            print(f"[{status}] {sev:<8} {f.rule_id} {f.file_path}:{f.line_number} - {f.message}")

        if sarif_file:
            sarif_text = sarif_rep._render_sarif(report, target_path)
            sarif_file.write_text(sarif_text, encoding="utf-8")
            print(f"SARIF report written to {sarif_file}")

        if json_file:
            json_text = json_rep._render_code(report, str(target_path))
            json_file.write_text(json_text, encoding="utf-8")
            print(f"JSON report written to {json_file}")

        print(
            f"Summary: {len(report.findings)} finding(s) total, "
            f"{len(blocking)} blocking (fail-on: {threshold.upper()})"
        )
        return 1 if blocking else 0

    def _run_web_ci(
        self,
        url: str,
        threshold: str,
        headers: dict[str, str],
        cookies: dict[str, str],
        json_file: Path | None = None,
    ) -> int:
        print(f"Sentinel CI (Web): Auditing {url}...")
        thresh_rank = _severity_rank(threshold)
        blue = self._blue(url, self.cfg._timeout() * 2, headers=headers, cookies=cookies)
        red = self._red(
            url,
            self.cfg._budget(),
            self.cfg._delay(),
            self.cfg._timeout(),
            headers=headers,
            cookies=cookies,
        )

        blocking_count = 0
        findings_out: list[dict[str, str]] = []

        if not isinstance(blue, Exception):
            for bf in getattr(blue, "findings", []) or []:
                sev = getattr(bf, "severity", Severity.MEDIUM)
                sev_val = sev.value if isinstance(sev, Severity) else str(sev)
                is_block = _severity_rank(sev_val) >= thresh_rank
                if is_block:
                    blocking_count += 1
                status = "BLOCKING" if is_block else "ADVISORY"
                print(f"[{status}] {sev_val:<8} {bf.rule_id} {url} - {bf.rule_name}")
                findings_out.append(
                    {"category": "headers", "rule": bf.rule_id, "detail": bf.rule_name}
                )

        if not isinstance(red, Exception):
            for rf in getattr(red, "findings", []) or []:
                is_critical = "flag" in getattr(rf, "evidence", "").lower()
                sev_val = "CRITICAL" if is_critical else "HIGH"
                is_block = _severity_rank(sev_val) >= thresh_rank
                if is_block:
                    blocking_count += 1
                status = "BLOCKING" if is_block else "ADVISORY"
                target_str = getattr(rf, "target", url)
                cat_str = getattr(rf, "category", "active")
                ev_str = getattr(rf, "evidence", "")
                print(f"[{status}] {sev_val:<8} {cat_str} {target_str} - {ev_str}")
                findings_out.append(
                    {"category": cat_str, "target": target_str, "evidence": ev_str}
                )

        if json_file:
            payload = json.dumps({"url": url, "findings": findings_out}, indent=2)
            json_file.write_text(payload, encoding="utf-8")
            print(f"JSON report written to {json_file}")

        print(
            f"Summary: {len(findings_out)} finding(s) total, "
            f"{blocking_count} blocking (fail-on: {threshold.upper()})"
        )
        return 1 if blocking_count > 0 else 0

    def _ci(self, args: list[str]) -> int:
        threshold = "high"
        sarif_path: Path | None = None
        json_path: Path | None = None
        target: str = "."

        headers, cookies = _parse_auth(args)
        idx = 0
        while idx < len(args):
            arg = args[idx]
            if arg == "--fail-on" and idx + 1 < len(args):
                threshold = args[idx + 1].lower()
                idx += 2
                continue
            if arg == "--sarif" and idx + 1 < len(args):
                sarif_path = Path(args[idx + 1]).resolve()
                idx += 2
                continue
            if arg == "--json" and idx + 1 < len(args):
                json_path = Path(args[idx + 1]).resolve()
                idx += 2
                continue
            if not arg.startswith("-") and arg != "ci":
                target = arg
            idx += 1

        is_url = target.startswith(self.cfg._schemes()) or (
            "://" in target or target.startswith(("localhost:", "127.0.0.1:", "192.168."))
        )
        if is_url:
            if not target.startswith(self.cfg._schemes()):
                target = "http://" + target
            return self._run_web_ci(target, threshold, headers, cookies, json_file=json_path)

        p = Path(target).resolve()
        return self._run_sast_ci(p, threshold, sarif_file=sarif_path, json_file=json_path)

    def _fix_cli(self, args: list[str]) -> int:
        write = "--write" in args or "-w" in args
        target = "."
        rules: set[str] | None = None
        idx = 0
        while idx < len(args):
            arg = args[idx]
            if arg == "--rule" and idx + 1 < len(args):
                rules = {args[idx + 1]}
                idx += 2
                continue
            if not arg.startswith("-") and arg != "fix":
                target = arg
            idx += 1

        target_path = Path(target).resolve()
        total, diff, applied = _fix(target_path, write=write, rules=rules)
        if total == 0:
            print("No auto-fixable findings found.")
            return 0

        print(f"Auto-Fix Summary: {total} remediation(s) across target.")
        for item in applied:
            print(f"  • {item}")
        if diff:
            print("\nUnified Diff:")
            print(diff)
        if write:
            print(f"\n[SUCCESS] Applied {total} fix(es) directly to source files.")
        else:
            print("\n[DRY RUN] Pass --write to apply these patches to disk.")
        return 0

    def _help(self) -> None:
        self.console.print(
            """[bold green]Sentinel Defensive Security Auditor & DevSecOps Gate[/bold green]

[bold]Usage:[/bold]
  sentinel                        Launch interactive scan mode
  sentinel <target> [auth flags]  Scan URL or code directory interactively
  sentinel ci <target> [options]  Run non-interactive CI/CD security gate
  sentinel fix <target> [options] Automatically fix common code vulnerabilities
  sentinel sca [target]           Audit dependencies for known CVEs (Python/Node)
  sentinel api <spec-or-url>      Audit OpenAPI/Swagger for OWASP API vulnerabilities
  sentinel install-hook           Install git pre-commit security & secret guard
  sentinel rules                  List loaded security rule catalogs

[bold]Authentication Options (for Web & API Scans):[/bold]
  --bearer <token>                Set Authorization: Bearer <token>
  -H, --header "Key: Value"       Set custom request header (can repeat)
  -b, --cookie "k=v; k2=v2"       Set cookie header

[bold]CI/CD Gate Options:[/bold]
  --fail-on [low|medium|high|critical]  Minimum severity to trigger exit code 1 (default: high)
  --sarif <file>                  Export findings in standard SARIF v2.1.0
  --json <file>                   Export findings in JSON format

[bold]Auto-Fix Options:[/bold]
  --write, -w                     Write patches to disk (default is dry-run diff)
  --rule <rule_id>                Apply fix only for specific rule (e.g. CMDI002)

[bold]General Options:[/bold]
  --version                       Print Sentinel version
  --info                          Print disclaimer and defensive scope
  --help, -h                      Show this help message"""
        )

    def _start(self, args: list[str] | None = None) -> None:
        raw_args = list(sys.argv[1:]) if args is None else args
        if "--version" in raw_args or "-v" in raw_args:
            self.console.print(f"Sentinel v{self.cfg._version()}")
            return
        if "--info" in raw_args:
            self.console.print(self.cfg._info())
            return
        if "--help" in raw_args or "-h" in raw_args:
            self._help()
            return

        if raw_args and raw_args[0] == "ci":
            code = self._ci(raw_args[1:])
            sys.exit(code)

        if raw_args and raw_args[0] == "fix":
            code = self._fix_cli(raw_args[1:])
            sys.exit(code)

        if raw_args and raw_args[0] in ("sca", "deps"):
            target = raw_args[1] if len(raw_args) > 1 else "."
            total, findings = sca._scan(target)
            print(sca._render(findings, target))
            sys.exit(1 if total > 0 else 0)

        if raw_args and raw_args[0] == "api":
            if len(raw_args) < 2:
                print("Usage: sentinel api <spec-file-or-url> [auth flags]")
                sys.exit(2)
            source = raw_args[1]
            headers, _ = _parse_auth(raw_args[2:])
            total, findings, origin = openapi._audit(source, headers=headers)
            print(openapi._render(findings, origin))
            sys.exit(1 if total > 0 else 0)

        if raw_args and raw_args[0] in ("install-hook", "hook"):
            sub = raw_args[1] if (raw_args[0] == "hook" and len(raw_args) > 1) else "install"
            if sub == "check":
                code = hook._check()
                sys.exit(code)
            ok, msg = hook._install()
            print(msg)
            sys.exit(0 if ok else 1)

        if raw_args and raw_args[0] == "rules":
            catalog = _load_all()
            total_rules = sum(len(rs.rules) for rs in catalog.values())
            self.console.print(
                f"[bold green]Loaded {len(catalog)} rule documents "
                f"({total_rules} rules total):[/bold green]"
            )
            for name, rs in sorted(catalog.items()):
                msg = f"  • [cyan]{name:<12}[/cyan] : {len(rs.rules)} rules ({rs.title})"
                self.console.print(msg)
            return

        headers, cookies = _parse_auth(raw_args)
        non_flag_args = [
            a for a in raw_args if not a.startswith("-") and a not in headers.values()
        ]
        target = non_flag_args[0] if non_flag_args else None
        if (
            target
            and not target.startswith(self.cfg._schemes())
            and not Path(target).resolve().exists()
        ):
            target = "http://" + target
        self._loop(target, headers=headers, cookies=cookies)

_auditor = Auditor()

def _main(argv: list[str] | None = None) -> None:
    _auditor._start(argv)

if __name__ == "__main__":
    _main()
