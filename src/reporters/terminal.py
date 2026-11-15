"""Rich-based terminal reporter for code and header audits."""

from __future__ import annotations

from collections.abc import Iterable, Sequence

from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from src.core.engine import AnalysisResult, Finding
from src.core.loader import Severity

SEVERITY_STYLES: dict[Severity, str] = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "bold yellow",
    Severity.LOW: "bold cyan",
}

SEVERITY_ORDER: tuple[Severity, ...] = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
)

SNIPPET_WIDTH: int = 52

SEVERITY_WIDTH: int = 8
RULE_WIDTH: int = 9
CWE_WIDTH: int = 8
CVE_WIDTH: int = 24
LOCATION_MIN: int = 14
LOCATION_MAX: int = 30
LOCATION_MAX_NARROW: int = 22
WIDE_CVE: int = 104
WIDE_CWE: int = 88


def _console(console: Console | None = None, no_color: bool = False) -> Console:
    """Return the console to render into."""
    if console is not None:
        return console
    return Console(no_color=no_color, highlight=False, soft_wrap=False)


def _severity_text(severity: Severity) -> Text:
    """Render a severity label with its colour style."""
    return Text(severity.value, style=SEVERITY_STYLES.get(severity, "white"))


def _trim_snippet(snippet: str, width: int = SNIPPET_WIDTH) -> str:
    """Trim a code snippet so it fits a table cell."""
    text = snippet.replace("\t", "    ").strip()
    if len(text) <= width:
        return text
    return text[: width - 3].rstrip() + "..."


def _findings_table(
    findings: Sequence[Finding],
    title: str,
    header_mode: bool = False,
    console: Console | None = None,
) -> Table:
    """Build the main findings table, dropping reference columns when narrow."""
    width = (console or _console()).width
    show_cwe = width >= WIDE_CWE
    show_cve = width >= WIDE_CVE

    if header_mode:
        labels = [_header_label(finding) for finding in findings]
        caption = "HEADER"
    else:
        labels = [finding._location() for finding in findings]
        caption = "LOCATION"

    longest = max((len(label) for label in labels), default=len(caption))
    location_floor = len(caption) if header_mode else LOCATION_MIN
    location_cap = LOCATION_MAX if header_mode or show_cwe else LOCATION_MAX_NARROW
    location_width = max(location_floor, min(longest + 1, location_cap))

    table = Table(
        title=title,
        title_style="bold",
        header_style="bold white",
        box=None,
        show_lines=False,
        pad_edge=False,
        expand=True,
    )
    table.add_column("SEVERITY", no_wrap=True, width=SEVERITY_WIDTH)
    table.add_column("RULE", no_wrap=True, width=RULE_WIDTH)
    table.add_column(caption, no_wrap=True, overflow="ellipsis", width=location_width)
    table.add_column("FINDING", overflow="fold", ratio=3)
    if show_cwe:
        table.add_column("CWE", no_wrap=True, width=CWE_WIDTH)
    if show_cve:
        table.add_column("CVE", no_wrap=True, width=CVE_WIDTH)

    for finding, label in zip(findings, labels, strict=True):
        row = [
            _severity_text(finding.severity),
            Text(finding.rule_id, style="dim"),
            Text(label),
            Text(finding.message, overflow="fold"),
        ]
        if show_cwe:
            row.append(Text(finding.cwe_id, style="dim"))
        if show_cve:
            row.append(Text(finding._cve_label(), style="dim"))
        table.add_row(*row)
    return table


def _header_label(finding: Finding) -> str:
    """Return the header or cookie name a header finding refers to."""
    snippet = finding.code_snippet.strip()
    if snippet:
        return snippet.split(":", 1)[0].strip()
    return "response"


def _summary_panel(result: AnalysisResult | Sequence[Finding], source: str) -> Panel:
    """Build the summary panel shown above the findings table."""
    if isinstance(result, AnalysisResult):
        findings = list(result.findings)
        counts = result._counts()
        lines = [
            Text.assemble(("Target: ", "bold"), (source, "")),
            Text.assemble(
                ("Files scanned: ", "bold"),
                (str(result.files_scanned), ""),
                ("    Files skipped: ", "bold"),
                (str(result.files_skipped), ""),
            ),
        ]
        if result.errors:
            lines.append(
                Text(
                    f"  {len(result.errors)} file(s)/analyzer(s) could not be read "
                    "(use --format json for details)",
                    style="yellow",
                )
            )
    else:
        findings = list(result)
        counts = {level.value: 0 for level in Severity}
        for item in findings:
            counts[item.severity.value] += 1
        lines = [Text.assemble(("Target: ", "bold"), (source, ""))]

    tally = Text()
    for index, level in enumerate(SEVERITY_ORDER):
        if index:
            tally.append("   ")
        tally.append(f"{level.value}: {counts.get(level.value, 0)}", style=SEVERITY_STYLES[level])

    lines.append(Text(""))
    lines.append(tally)
    return Panel(Group(*lines), title="Sentinel audit summary", border_style="blue")


def _remediation_section(findings: Sequence[Finding]) -> Group | None:
    """Build a compact remediation reference for triggered rules."""
    by_rule: dict[str, Finding] = {}
    for finding in findings:
        by_rule.setdefault(finding.rule_id, finding)
    if not by_rule:
        return None

    lines: list[Text] = []
    for rule_id in sorted(by_rule):
        finding = by_rule[rule_id]
        header = Text.assemble(
            (f"{rule_id}", "bold"),
            (f"  {finding.rule_name}", ""),
            (f"  ({finding.category}, {finding.cwe_id})", "dim"),
            (f"  {finding._cve_label()}", "dim"),
        )
        lines.append(header)
        if finding.remediation:
            lines.append(Text(f"    fix: {finding.remediation}", style="green"))
    return Group(*lines)


def _render_findings(
    result: AnalysisResult | Sequence[Finding],
    source: str,
    title: str = "Findings",
    console: Console | None = None,
    no_color: bool = False,
    show_remediation: bool = True,
) -> None:
    """Render an analysis result to the terminal."""
    out = _console(console, no_color=no_color)
    findings = list(result.findings) if isinstance(result, AnalysisResult) else list(result)

    out.print(_summary_panel(result, source))

    if not findings:
        out.print(
            Panel(
                Text("No findings. Static checks passed for the scanned scope.", style="green"),
                border_style="green",
            )
        )
        return

    out.print(_findings_table(findings, title, console=out))

    remediation = _remediation_section(findings) if show_remediation else None
    if remediation is not None:
        out.print(Panel(remediation, title="Remediation guidance", border_style="cyan"))

    if isinstance(result, AnalysisResult) and result.errors:
        out.print(_errors_panel(result.errors))


def _errors_panel(errors: Iterable[str]) -> Panel:
    """Render the list of files that could not be analyzed."""
    text = Text()
    for index, error in enumerate(errors):
        if index:
            text.append("\n")
        text.append(f"- {error}", style="yellow")
    return Panel(text, title="Analysis notices", border_style="yellow")


def _render_exit_hint(
    blocking: int, console: Console | None = None, no_color: bool = False
) -> None:
    """Print the pass/fail verdict used by CI pipelines."""
    out = _console(console, no_color=no_color)
    if blocking:
        out.print(
            Text(
                f"FAIL: {blocking} HIGH/CRITICAL finding(s) detected. Remediate before shipping.",
                style="bold white on red",
            )
        )
    else:
        out.print(Text("PASS: no HIGH or CRITICAL findings detected.", style="bold green"))


def _render_error_hint(console: Console | None = None, no_color: bool = False) -> None:
    """Print the verdict used when no response could be audited."""
    out = _console(console, no_color=no_color)
    out.print(
        Text(
            "ERROR: the audit could not complete; no verdict was produced.",
            style="bold white on red",
        )
    )


def _render_headers_report(
    report,
    console: Console | None = None,
    no_color: bool = False,
) -> None:
    """Render a passive header audit report."""
    out = _console(console, no_color=no_color)

    if getattr(report, "whitelisted", False):
        out.print(Text.assemble(("URL : ", "bold"), (report.url, "")))
        out.print(
            Text.assemble(
                ("status : ", "bold"), ("WHITELISTED (domain matched allowlist)", "bold green")
            )
        )
        return

    out.print(_summary_panel(list(report.findings), report.url))

    info = Table(box=None, show_header=False, pad_edge=False)
    info.add_column("key", style="bold", width=16)
    info.add_column("value")
    info.add_row("Status", str(report.status_code))
    info.add_row("Final URL", report.final_url)
    info.add_row("Cookies seen", str(getattr(report, "cookie_count", 0)))
    info.add_row("Headers seen", str(len(getattr(report, "present_headers", ()) or ())))
    out.print(Panel(info, title="Response", border_style="blue"))

    if report.errors:
        out.print(_errors_panel(report.errors))

    if not getattr(report, "present_headers", ()):
        out.print(
            Panel(
                Text(
                    "No response could be audited; header checks were skipped. This is not a pass.",
                    style="bold red" if report.errors else "yellow",
                ),
                border_style="red" if report.errors else "yellow",
            )
        )
        return

    if not report.findings:
        out.print(
            Panel(
                Text("All audited security headers are present.", style="green"),
                border_style="green",
            )
        )
        return

    out.print(
        _findings_table(list(report.findings), "Header findings", header_mode=True, console=out)
    )
    remediation = _remediation_section(list(report.findings))
    if remediation is not None:
        out.print(Panel(remediation, title="Remediation guidance", border_style="cyan"))


CATEGORY_LABELS: tuple[str, ...] = (
    "xss",
    "sql injection",
    "headers & cookies",
    "cors & info leak",
    "ssrf & redirects",
    "stack & shells",
)
LABEL_WIDTH: int = max(len(label) for label in CATEGORY_LABELS)
VULNERABLE_STYLE: str = "bold red"
HARDENING_STYLE: str = "bold yellow"
SAFE_STYLE: str = "bold green"

STATUS_STYLES: dict[str, str] = {
    "VULNERABLE": VULNERABLE_STYLE,
    "HARDENING NEEDED": HARDENING_STYLE,
    "SAFE": SAFE_STYLE,
}

MAX_REASONS: int = 3


def _page_count(report) -> int:
    """Return how many pages the report inspected, if it tracks them."""
    return len(getattr(report, "pages", ()) or ())


def _unreachable(report) -> bool:
    """Return True when no response was received, so verdicts are meaningless."""
    return bool(getattr(report, "errors", ())) and not getattr(report, "status_code", 0)


def _trim_reasons(reasons: Sequence[str], limit: int = MAX_REASONS) -> str:
    """Join reasons for display, summarizing anything beyond the limit."""
    if not reasons:
        return "indicators detected"
    shown = list(reasons[:limit])
    extra = len(reasons) - len(shown)
    if extra > 0:
        shown.append(f"+{extra} more")
    return ", ".join(shown)


def _status_style(status: str) -> str:
    """Return the Rich style for a status label."""
    return STATUS_STYLES.get(status, SAFE_STYLE)


def _category_lines(report, verbose: bool = False) -> list[tuple[str, str, str]]:
    """Return (label, status, detail) rows for a web report.

    ``verbose`` keeps every reason instead of truncating with ``+N more``.
    """
    rows: list[tuple[str, str, str]] = []
    for label in CATEGORY_LABELS:
        category = report._category(label)
        status = category._label()
        if status == "SAFE":
            detail = "no indicators detected"
        else:
            detail = _reason_text(category.reasons, verbose)
        rows.append((label, status, detail))
    return rows


def _plain_line(
    label: str,
    status: str,
    detail: str,
) -> Text:
    """Build one coloured ``label : STATUS (detail)`` plain-text line."""
    line = Text()
    line.append(f"{label} : ")
    line.append(status, style=_status_style(status))
    line.append(f" ({detail})")
    return line


def _reason_text(reasons: Sequence[str], verbose: bool) -> str:
    """Join reasons, truncating only when the compact view requests it."""
    if not reasons:
        return "no indicators detected"
    if verbose:
        return ", ".join(reasons)
    return _trim_reasons(reasons)


def _render_simple(
    report,
    console: Console | None = None,
    no_color: bool = False,
    show_errors: bool = True,
) -> None:
    """Render the compact URL summary as plain lines (no borders)."""
    out = _console(console, no_color=no_color)

    out.print(Text.assemble(("URL : ", "bold"), (report.url, "")))

    if getattr(report, "whitelisted", False):
        out.print(
            Text.assemble(
                ("status : ", "bold"), ("WHITELISTED (domain matched allowlist)", "bold green")
            )
        )
        return

    if _unreachable(report):
        out.print(Text("unreachable : no response could be audited", style="bold red"))
        if show_errors:
            for error in report.errors:
                out.print(Text(f"  ! {error}", style="yellow"))
        return

    if _page_count(report) > 1:
        out.print(Text(f"pages : {_page_count(report)} inspected"))

    for label, status, detail in _category_lines(report):
        out.print(_plain_line(label, status, detail))

    if show_errors and report.errors:
        for error in report.errors:
            out.print(Text(f"  ! {error}", style="yellow"))


def _render_web_report(
    report,
    console: Console | None = None,
    no_color: bool = False,
) -> None:
    """Render the detailed URL report as plain lines (no borders).

    Shows the response status, every inspected URL and the untruncated list of
    reasons behind each category verdict. No ``Panel`` or ``Table`` is used, so
    the output stays greppable and copy-paste friendly.
    """
    out = _console(console, no_color=no_color)

    out.print(Text.assemble(("URL : ", "bold"), (report.url, "")))

    if getattr(report, "whitelisted", False):
        out.print(
            Text.assemble(
                ("status : ", "bold"), ("WHITELISTED (domain matched allowlist)", "bold green")
            )
        )
        return

    if _unreachable(report):
        out.print(Text("unreachable : no response could be audited", style="bold red"))
        for error in report.errors:
            out.print(Text(f"  ! {error}", style="yellow"))
        return

    out.print(Text.assemble(("status : ", "bold"), (str(report.status_code), "")))

    pages = getattr(report, "pages", ()) or ()
    if pages:
        out.print(Text(f"pages inspected ({len(pages)}) :", style="bold"))
        for page in pages:
            out.print(Text(f"  - {page}"))

    for label, status, detail in _category_lines(report, verbose=True):
        out.print(_plain_line(label, status, detail))

    if report.errors:
        for error in report.errors:
            out.print(Text(f"  ! {error}", style="yellow"))


def _simple_text(report, verbose: bool = False) -> str:
    """Return the summary as plain text without colour (for logs and tests)."""
    if getattr(report, "whitelisted", False):
        return f"URL : {report.url}\nstatus : WHITELISTED (domain matched allowlist)\n"

    lines = [f"URL : {report.url}"]
    if verbose:
        lines.append(f"status : {report.status_code}")
        pages = getattr(report, "pages", ()) or ()
        if pages:
            lines.append(f"pages inspected ({len(pages)}) :")
            lines.extend(f"  - {page}" for page in pages)
    elif _page_count(report) > 1:
        lines.append(f"pages : {_page_count(report)} inspected")
    for label, status, detail in _category_lines(report, verbose=verbose):
        lines.append(f"{label} : {status} ({detail})")
    if report.errors:
        lines.extend(f"  ! {error}" for error in report.errors)
    return "\n".join(lines) + "\n"
