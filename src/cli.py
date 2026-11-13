"""Typer entry point for the Sentinel defensive security auditor.

Commands:
    audit-code <path>     Static AST analysis of Python sources.
    audit-headers <url>   Passive HTTP security header audit.
    rules                 Validate and list the loaded rule documents.

Every command returns exit code 0 on pass, 1 when HIGH/CRITICAL findings are
present, and 2 on usage or runtime errors, so pipelines can gate on results.
"""

from __future__ import annotations

import subprocess
import sys
from enum import Enum
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from src.analyzers import api as api_analyzer
from src.analyzers import auth as auth_analyzer
from src.analyzers import client as client_analyzer
from src.analyzers import cloud as cloud_analyzer
from src.analyzers import cmdi as cmdi_analyzer
from src.analyzers import cve as cve_analyzer
from src.analyzers import deps as deps_analyzer
from src.analyzers import deserial as deserial_analyzer
from src.analyzers import headers as headers_analyzer
from src.analyzers import host as host_analyzer
from src.analyzers import idor as idor_analyzer
from src.analyzers import logic as logic_analyzer
from src.analyzers import redos as redos_analyzer
from src.analyzers import secrets as secrets_analyzer
from src.analyzers import sqli as sqli_analyzer
from src.analyzers import ssti as ssti_analyzer
from src.analyzers import ssrf as ssrf_analyzer
from src.analyzers import tamper as tamper_analyzer
from src.analyzers import traversal as traversal_analyzer
from src.analyzers import xss as xss_analyzer
from src.analyzers import xxe as xxe_analyzer
from src.core import engine
from src.core.loader import RuleLoadError, _load_all, _validate_all
from src.reporters import json as json_reporter
from src.reporters import sarif as sarif_reporter
from src.reporters import terminal as terminal_reporter

EXIT_OK: int = 0
EXIT_FINDINGS: int = 1
EXIT_ERROR: int = 2

APP_NAME: str = "sentinel"
URL_SCHEMES: tuple[str, ...] = ("http://", "https://")

APP = typer.Typer(
    name=APP_NAME,
    help=(
        "Defensive web security auditor: static AST analysis across 167 rules "
        "and 20 CWE categories (SQLi, XSS, command injection, path traversal, secrets, SSRF, "
        "deserialization, XXE, SSTI, auth/TLS, ReDoS, API/GraphQL, deprecated "
        "modules, host header injection, IDOR, cloud storage, client storage, "
        "rate limiting & request tampering, race conditions & business logic) "
        "plus 100-CVE knowledge base and 4-layer passive HTTP web surface auditing. "
        "Detection only - no exploitation."
    ),
    add_completion=False,
    no_args_is_help=True,
    rich_markup_mode="rich",
)


class OutputFormat(str, Enum):
    """Supported report formats."""

    CLI = "cli"
    JSON = "json"
    SARIF = "sarif"


def _err(message: str) -> None:
    """Print an error message to stderr without rich markup interference."""
    typer.secho(f"error: {message}", fg=typer.colors.RED, err=True)


def _analyzers() -> list:
    """Return the AST analyzer modules in a deterministic order."""
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
    ]


def _exit_for(blocking: bool) -> None:
    """Raise the Typer exit matching the pass/fail verdict."""
    raise typer.Exit(code=EXIT_FINDINGS if blocking else EXIT_OK)


def _write(out_path: Path, text: str) -> None:
    """Write report output to a file, reporting failures cleanly."""
    try:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(text + "\n", encoding="utf-8")
    except OSError as exc:
        raise typer.BadParameter(f"cannot write report to {out_path}: {exc}") from exc


def _git_changed_files(root: Path | None = None) -> list[Path]:
    """Query git status and git diff to find modified or new Python files."""
    target_dir = root.resolve() if root else Path.cwd().resolve()
    seen: set[Path] = set()
    files: list[Path] = []

    def _collect(output: str) -> None:
        for raw_line in output.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            if " -> " in line:
                rel_path = line.split(" -> ")[-1].strip()
            elif len(line) >= 3 and (line[0] in " MADRCU?!" or line[1] in " MADRCU?!"):
                rel_path = line[2:].strip().strip('"')
            else:
                rel_path = line.strip().strip('"')
            candidate = (target_dir / rel_path).resolve()
            if candidate.suffix.lower() in engine.SOURCE_SUFFIXES and candidate.is_file():
                if candidate not in seen:
                    seen.add(candidate)
                    files.append(candidate)

    try:
        proc_diff = subprocess.run(
            ["git", "diff", "--name-only", "HEAD"],
            cwd=target_dir,
            capture_output=True,
            text=True,
            check=False,
        )
        if proc_diff.returncode == 0:
            _collect(proc_diff.stdout)
    except (OSError, ValueError):
        pass

    try:
        proc_status = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=target_dir,
            capture_output=True,
            text=True,
            check=False,
        )
        if proc_status.returncode == 0:
            _collect(proc_status.stdout)
    except (OSError, ValueError):
        pass

    files.sort()
    return files


@APP.command(name="audit-code")
def _audit_code(
    path: Annotated[
        Path | None,
        typer.Argument(
            help="Python file or directory to analyze (omit when using --changed).",
        ),
    ] = None,
    changed: Annotated[
        bool,
        typer.Option("--changed", "-c", help="Audit only modified and newly added git files."),
    ] = False,
    format: Annotated[
        OutputFormat,
        typer.Option("--format", "-f", help="Report format.", case_sensitive=False),
    ] = OutputFormat.CLI,
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Write the report to this file."),
    ] = None,
    no_color: Annotated[
        bool,
        typer.Option("--no-color", help="Disable ANSI colour in terminal output."),
    ] = False,
    quiet: Annotated[
        bool,
        typer.Option("--quiet", "-q", help="Suppress the remediation guidance section."),
    ] = False,
    exclude: Annotated[
        list[str] | None,
        typer.Option(
            "--exclude",
            "-x",
            help="Additional directory name to skip (repeatable).",
        ),
    ] = None,
    fail_on: Annotated[
        str,
        typer.Option(
            "--fail-on",
            help="Lowest severity that fails the run: none, low, medium, high, critical.",
            case_sensitive=False,
        ),
    ] = "high",
) -> None:
    """Statically analyze Python source for injection and misconfiguration patterns."""
    if path is None and not changed:
        _err("missing target path (e.g. 'sentinel audit-code src' or 'sentinel audit-code --changed')")
        raise typer.Exit(code=EXIT_ERROR)

    excluded = engine.DEFAULT_EXCLUDED | {item for item in (exclude or []) if item}
    threshold = _threshold(fail_on)
    scan_target = path if path is not None else Path(".")

    try:
        if changed:
            changed_files = _git_changed_files(scan_target)
            files_to_scan = [
                f for f in changed_files if not any(part in excluded for part in f.parts)
            ]
            result = engine._run_analyzers_on_files(files_to_scan, _analyzers(), root=scan_target)
        else:
            result = engine._run_analyzers(scan_target, _analyzers(), excluded=excluded)
    except FileNotFoundError as exc:
        _err(str(exc))
        raise typer.Exit(code=EXIT_ERROR) from exc
    except ValueError as exc:
        _err(str(exc))
        raise typer.Exit(code=EXIT_ERROR) from exc
    except RuleLoadError as exc:
        _err(f"rule loading failed: {exc}")
        raise typer.Exit(code=EXIT_ERROR) from exc

    blocking = _blocking_count(result.findings, threshold)

    if format is OutputFormat.JSON:
        text = json_reporter._render_code(result, str(scan_target))
        if output is not None:
            _write(output, text)
            typer.echo(f"JSON report written to {output}", err=True)
        else:
            typer.echo(text)
    elif format is OutputFormat.SARIF:
        text = sarif_reporter._render_sarif(result, target=scan_target)
        if output is not None:
            _write(output, text)
            typer.echo(f"SARIF report written to {output}", err=True)
        else:
            typer.echo(text)
    else:
        title = "Static analysis findings" if not changed else "Static analysis findings (git changed files)"
        terminal_reporter._render_findings(
            result,
            source=str(scan_target),
            title=title,
            no_color=no_color,
            show_remediation=not quiet,
        )
        if not quiet:
            terminal_reporter._render_exit_hint(blocking, no_color=no_color)

    raise typer.Exit(code=EXIT_FINDINGS if blocking else EXIT_OK)


@APP.command(name="changed")
def _changed(
    format: Annotated[
        OutputFormat,
        typer.Option("--format", "-f", help="Report format.", case_sensitive=False),
    ] = OutputFormat.CLI,
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Write the report to this file."),
    ] = None,
    no_color: Annotated[
        bool,
        typer.Option("--no-color", help="Disable ANSI colour in terminal output."),
    ] = False,
    quiet: Annotated[
        bool,
        typer.Option("--quiet", "-q", help="Suppress the remediation guidance section."),
    ] = False,
    exclude: Annotated[
        list[str] | None,
        typer.Option(
            "--exclude",
            "-x",
            help="Additional directory name to skip (repeatable).",
        ),
    ] = None,
    fail_on: Annotated[
        str,
        typer.Option(
            "--fail-on",
            help="Lowest severity that fails the run: none, low, medium, high, critical.",
            case_sensitive=False,
        ),
    ] = "high",
) -> None:
    """Audit only modified and newly added git files."""
    _audit_code(
        path=Path("."),
        changed=True,
        format=format,
        output=output,
        no_color=no_color,
        quiet=quiet,
        exclude=exclude,
        fail_on=fail_on,
    )


@APP.command(name="audit-headers")
def _audit_headers(
    url: Annotated[
        str,
        typer.Argument(help="Target URL. https:// is assumed when no scheme is given."),
    ],
    format: Annotated[
        OutputFormat,
        typer.Option("--format", "-f", help="Report format.", case_sensitive=False),
    ] = OutputFormat.CLI,
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Write the JSON report to this file."),
    ] = None,
    timeout: Annotated[
        float,
        typer.Option("--timeout", help="Request timeout in seconds.", min=0.5, max=120.0),
    ] = headers_analyzer.DEFAULT_TIMEOUT,
    no_redirects: Annotated[
        bool,
        typer.Option("--no-redirects", help="Do not follow HTTP redirects."),
    ] = False,
    no_color: Annotated[
        bool,
        typer.Option("--no-color", help="Disable ANSI colour in terminal output."),
    ] = False,
    fail_on: Annotated[
        str,
        typer.Option(
            "--fail-on",
            help="Lowest severity that fails the run: none, low, medium, high, critical.",
            case_sensitive=False,
        ),
    ] = "high",
    web: Annotated[
        bool,
        typer.Option(
            "--web",
            help="Run the unified xss / sql injection / headers check (compact summary).",
            hidden=True,
        ),
    ] = False,
    verbose: Annotated[
        bool,
        typer.Option("--verbose", help="Show detailed tables instead of the compact summary."),
    ] = False,
    deep: Annotated[
        bool,
        typer.Option(
            "--deep/--no-deep",
            help="Also inspect up to 25 same-origin pages discovered from links and forms.",
        ),
    ] = True,
    probe: Annotated[
        bool,
        typer.Option(
            "--probe/--no-probe",
            help="Send one benign canary value to existing GET parameters to confirm reflection.",
        ),
    ] = True,
) -> None:
    """Audit HTTP headers, cookies, markup and redirect surface with passive requests."""
    # ``--verbose`` selects the unified check even without the hidden ``--web``
    # marker, so the detailed renderer and the category verdicts agree.
    if web or verbose:
        _run_url_audit(
            url=url,
            format=format,
            output=output,
            timeout=timeout,
            follow_redirects=not no_redirects,
            no_color=no_color,
            verbose=verbose,
            fail_on=fail_on,
            deep=deep,
            probe=probe,
        )
        return

    _run_header_audit(
        url=url,
        format=format,
        output=output,
        timeout=timeout,
        follow_redirects=not no_redirects,
        no_color=no_color,
        fail_on=fail_on,
    )


def _echo_table(title: str, headers: tuple[str, ...], rows: list[tuple[str, ...]]) -> None:
    """Print a borderless, width-fitted table of plain text rows."""
    widths = [len(header) for header in headers]
    for row in rows:
        for index, cell in enumerate(row):
            widths[index] = max(widths[index], len(str(cell)))

    typer.echo(title)
    typer.echo("  ".join(header.ljust(widths[index]) for index, header in enumerate(headers)))
    typer.echo("  ".join("-" * width for width in widths))
    for row in rows:
        typer.echo(
            "  ".join(str(cell).ljust(widths[index]) for index, cell in enumerate(row))
        )


@APP.command(name="rules")
def _rules(
    rule_dir: Annotated[
        Path | None,
        typer.Option("--dir", help="Load rule documents from a custom directory."),
    ] = None,
    show: Annotated[
        bool,
        typer.Option("--show", help="List every rule with severity, CWE, CVE and date."),
    ] = False,
) -> None:
    """Validate the JSON rule documents and summarize them."""
    console = Console()

    try:
        summaries = _validate_all(rule_dir)
        catalog = _load_all(rule_dir)
    except RuleLoadError as exc:
        _err(f"rule validation failed: {exc}")
        raise typer.Exit(code=EXIT_ERROR) from exc

    _echo_table(
        "Rule documents",
        ("Analyzer", "Rules", "Enabled", "Schema"),
        [
            (
                analyzer,
                str(len(ruleset.rules)),
                str(len(ruleset._enabled_rules())),
                ruleset.schema_version,
            )
            for analyzer, ruleset in sorted(catalog.items())
        ],
    )

    if show:
        _echo_table(
            "Rules",
            ("ID", "Severity", "CWE", "CVE", "Published", "Category", "Name"),
            [
                (
                    rule.rule_id,
                    rule.severity.value,
                    rule.cwe_id,
                    rule.cve,
                    rule.cve_date,
                    rule.category,
                    rule.name,
                )
                for ruleset in sorted(catalog.values(), key=lambda item: item.analyzer)
                for rule in sorted(ruleset.rules, key=lambda item: item.rule_id)
            ],
        )

    raise typer.Exit(code=EXIT_OK)


def _threshold(value: str) -> int:
    """Map a --fail-on label to the minimum rank that fails the run."""
    label = (value or "").strip().lower()
    mapping = {"none": 99, "low": 0, "medium": 1, "high": 2, "critical": 3}
    if label not in mapping:
        raise typer.BadParameter(
            f"invalid --fail-on value {value!r}; choose from {', '.join(mapping)}"
        )
    return mapping[label]


def _blocking_count(findings, threshold_rank: int) -> int:
    """Count findings at or above the configured failing severity."""
    return sum(1 for finding in findings if finding.severity._rank() >= threshold_rank)


def _version_callback(value: bool) -> None:
    """Print the tool version and exit."""
    if value:
        typer.echo(f"{APP_NAME} {json_reporter.TOOL_VERSION}")
        raise typer.Exit(code=EXIT_OK)


def _is_url(target: str) -> bool:
    """Return True when a target looks like an http:// or https:// URL."""
    candidate = (target or "").strip().lower()
    return candidate.startswith(URL_SCHEMES)


def _looks_like_host(target: str) -> bool:
    """Return True when a target is a bare host (no scheme, no path separator)."""
    candidate = (target or "").strip()
    if not candidate or candidate.startswith("-"):
        return False
    if any(separator in candidate for separator in ("/", "\\", " ")):
        return False
    host = candidate.split(":", 1)[0]
    return "." in host and not host.endswith(".py")


def _run_url_audit(
    url: str,
    format: OutputFormat,
    output: Path | None,
    timeout: float,
    follow_redirects: bool,
    no_color: bool,
    verbose: bool = False,
    fail_on: str = "high",
    deep: bool = True,
    probe: bool = True,
) -> None:
    """Check XSS, SQL injection and headers for a URL and exit accordingly.

    The compact one-line-per-category summary is the default; ``--verbose`` or
    ``--format json`` expose the detailed tables and full finding list.
    """
    del fail_on  # any vulnerable category fails the run for the unified check

    try:
        report = headers_analyzer._audit_web(
            url,
            timeout=timeout,
            follow_redirects=follow_redirects,
            probe=probe,
            deep=deep,
        )
    except ValueError as exc:
        _err(str(exc))
        raise typer.Exit(code=EXIT_ERROR) from exc
    except RuleLoadError as exc:
        _err(f"rule loading failed: {exc}")
        raise typer.Exit(code=EXIT_ERROR) from exc

    unreachable = bool(report.errors) and report.status_code == 0

    if format is OutputFormat.JSON:
        text = json_reporter._render_web(report)
        if output is not None:
            _write(output, text)
            typer.echo(f"JSON report written to {output}", err=True)
        else:
            typer.echo(text)
    elif verbose:
        terminal_reporter._render_web_report(report, no_color=no_color)
    else:
        terminal_reporter._render_simple(report, no_color=no_color)

    if unreachable:
        raise typer.Exit(code=EXIT_ERROR)

    raise typer.Exit(code=EXIT_FINDINGS if report._has_blocking() else EXIT_OK)


def _run_header_audit(
    url: str,
    format: OutputFormat,
    output: Path | None,
    timeout: float,
    follow_redirects: bool,
    no_color: bool,
    fail_on: str,
) -> None:
    """Audit one URL and exit with the appropriate status code."""
    threshold = _threshold(fail_on)

    try:
        report = headers_analyzer._analyze(
            url,
            timeout=timeout,
            follow_redirects=follow_redirects,
        )
    except ValueError as exc:
        _err(str(exc))
        raise typer.Exit(code=EXIT_ERROR) from exc
    except RuleLoadError as exc:
        _err(f"rule loading failed: {exc}")
        raise typer.Exit(code=EXIT_ERROR) from exc

    blocking = _blocking_count(report.findings, threshold)
    unreachable = bool(report.errors) and not report.present_headers

    if format is OutputFormat.JSON:
        text = json_reporter._render_headers(report)
        if output is not None:
            _write(output, text)
            typer.echo(f"JSON report written to {output}", err=True)
        else:
            typer.echo(text)
    else:
        terminal_reporter._render_headers_report(report, no_color=no_color)
        if unreachable:
            terminal_reporter._render_error_hint(no_color=no_color)
        else:
            terminal_reporter._render_exit_hint(blocking, no_color=no_color)

    if unreachable:
        raise typer.Exit(code=EXIT_ERROR)

    raise typer.Exit(code=EXIT_FINDINGS if blocking else EXIT_OK)


@APP.callback()
def _root(
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            "-v",
            help="Show the tool version and exit.",
            callback=_version_callback,
            is_eager=True,
        ),
    ] = False,
) -> None:
    """Defensive, passive-only security auditing for Python web applications."""
    del version
    return None


ROOT_OPTIONS_WITH_VALUE: frozenset[str] = frozenset(
    {"--format", "-f", "--output", "-o", "--timeout", "--fail-on", "--exclude", "-x"}
)
ROOT_FLAGS: frozenset[str] = frozenset(
    {
        "--no-redirects",
        "--no-color",
        "--version",
        "-v",
        "--verbose",
        "--deep",
        "--no-deep",
        "--probe",
        "--no-probe",
        "--quiet",
        "-q",
        "--changed",
        "-c",
    }
)


def _route_shorthand(argv: list[str]) -> list[str]:
    """Rewrite shorthand invocations into the appropriate subcommand.

    * ``sentinel <url> [opts]`` -> ``sentinel audit-headers --web <url> [opts]``
    * ``sentinel <path> [opts]`` -> ``sentinel audit-code <path> [opts]``
    * Existing subcommands (``audit-code``, ``audit-headers``, ``changed``, ``rules``)
      and root flags (``--help``, ``--version``) remain unchanged.
    """
    if not argv:
        return argv

    head = argv[0]
    if head.startswith("-"):
        return argv

    known_commands = set(_command_names())
    if head in known_commands:
        return argv

    if _is_url(head) or _looks_like_host(head):
        # Validate that the trailing options belong to the header audit surface.
        index = 1
        while index < len(argv):
            token = argv[index]
            if token.startswith("--") and "=" in token:
                name = token.split("=", 1)[0]
                if name not in ROOT_OPTIONS_WITH_VALUE and name not in ROOT_FLAGS:
                    return argv
                index += 1
                continue
            if token in ROOT_FLAGS:
                index += 1
                continue
            if token in ROOT_OPTIONS_WITH_VALUE:
                index += 2
                continue
            if token.startswith("-") and token not in {"-h", "--help"}:
                return argv
            # Any other positional after the URL is not a valid shorthand form.
            return argv

        tail = argv[1:]
        verbose = "--verbose" in tail
        if verbose:
            # Keep --verbose so the detailed renderer is selected; only the hidden
            # --web marker is omitted, since --verbose implies the unified check.
            return ["audit-headers", head, *tail]
        forwarded = [token for token in tail if token != "--verbose"]
        return ["audit-headers", "--web", head, *forwarded]

    # Non-URL, non-command positional: route to audit-code <head> [*tail]
    return ["audit-code", head, *argv[1:]]


def _command_names() -> list[str]:
    """Return the registered subcommand names."""
    return [command.name for command in APP.registered_commands if command.name]


def _main(argv: list[str] | None = None) -> None:
    """Console-script entry point.

    Supports the shorthand ``sentinel <url>`` form by rewriting the argument list
    before Typer parses it, and prints help when no arguments are supplied.
    """
    arguments = list(sys.argv[1:] if argv is None else argv)

    if not arguments:
        APP(args=["--help"], prog_name=APP_NAME)
        return None

    arguments = _route_shorthand(arguments)

    try:
        APP(args=arguments, prog_name=APP_NAME)
    except KeyboardInterrupt:
        typer.secho("interrupted", fg=typer.colors.YELLOW, err=True)
        raise SystemExit(130) from None
    return None


if __name__ == "__main__":
    sys.exit(_main())
