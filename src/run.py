from __future__ import annotations
import concurrent.futures, sys, time, urllib.parse
from rich.align import Align
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from src.active import scan as active_scan
from src.analyzers import headers as headers_analyzer

_CONSOLE = Console()

class Config:
    def _version(self) -> str:
        return "1.2"

    def _info(self) -> str:
        return (
            "Sentinel v1.2 - Defensive Security Auditor\n"
            "Preliminary security assessment and defensive educational research only.\n"
            "Designed to audit web applications and identify defensive gaps.\n"
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

class Auditor:
    def __init__(self) -> None:
        self.cfg = Config()
        self.console = _CONSOLE

    def _clean(self) -> None:
        self.console.clear()

    def _host(self, url: str) -> str:
        parsed = urllib.parse.urlparse(url)
        return parsed.netloc or parsed.path or url

    def _blue(self, url: str, timeout: float):
        try:
            return headers_analyzer._audit_web(
                url, timeout=timeout, follow_redirects=True, probe=True, deep=True
            )
        except Exception as exc:  # noqa: BLE001
            return exc

    def _red(self, url: str, budget: int, delay: float, timeout: float):
        try:
            return active_scan._run(
                url, crawl=True, budget=budget, delay=delay, timeout=timeout, max_pages=60
            )
        except Exception as exc:  # noqa: BLE001
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

    def _scan(self, url: str) -> tuple:
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
            bf = pool.submit(self._blue, url, self.cfg._timeout() * 2)
            rf = pool.submit(
                self._red,
                url,
                self.cfg._budget(),
                self.cfg._delay(),
                self.cfg._timeout(),
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

    def _loop(self, initial: str | None = None) -> None:
        target = initial
        while True:
            if not target:
                self._clean()
                self.console.print(Panel(self.cfg._banner(), border_style="green"))
                target = self._prompt()
                if not target:
                    break
            self._clean()
            blue, red = self._scan(target)
            self._show(target, blue, red)
            target = None
            if not self._wait():
                break
            self._clean()
        self._clean()
        self.console.print("[dim]Sentinel terminated. Stay safe![/dim]")

    def _start(self, args: list[str] | None = None) -> None:
        raw_args = list(sys.argv[1:]) if args is None else args
        if "--version" in raw_args:
            self.console.print(f"Sentinel v{self.cfg._version()}")
            return
        if "--info" in raw_args:
            self.console.print(self.cfg._info())
            return
        target = raw_args[0] if raw_args else None
        if target and not target.startswith(self.cfg._schemes()):
            target = "http://" + target
        self._loop(target)

_auditor = Auditor()

def _main(argv: list[str] | None = None) -> None:
    _auditor._start(argv)

if __name__ == "__main__":
    _main()
