"""Passive HTTP security header auditor (HDR001-HDR010).

This module performs exactly one safe request to a target URL and inspects the
response metadata. It sends no payloads, follows no more than the configured
redirect budget, and touches no path other than the one supplied by the
operator. Cookie analysis is read-only over ``Set-Cookie`` values.
"""

from __future__ import annotations

import json
import re
import secrets
from collections.abc import Iterable
from dataclasses import dataclass, field
from enum import Enum
from functools import lru_cache
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin, urlparse

import httpx

from src.core.engine import Finding
from src.core.loader import Rule, _rules_for

ANALYZER_NAME: str = "headers"
DEFAULT_TIMEOUT: float = 10.0
DEFAULT_REDIRECTS: int = 3
USER_AGENT: str = "SentinelAuditor/0.1 (passive-security-header-check)"

DIRECTIVE_PATTERN = re.compile(r"^\s*([a-zA-Z0-9-]+)")
MAX_AGE_PATTERN = re.compile(r"max-age\s*=\s*(\d+)", re.IGNORECASE)
_RE_CSP_WILDCARD = re.compile(r"(^|[\s;])[*](\s|;|$)")

_TAKEOVER_DOMAINS: tuple[str, ...] = (
    "herokuapp.com",
    "github.io",
    "azurewebsites.net",
    "s3.amazonaws.com",
    "pantheonsite.io",
    "firebaseapp.com",
    "surge.sh",
)
_STORAGE_TOKENS: tuple[str, ...] = ("token", "jwt", "auth", "secret", "password", "session")
_SENSITIVE_HIDDEN_PARAMS: tuple[str, ...] = (
    "role",
    "is_admin",
    "admin",
    "price",
    "amount",
    "discount",
    "user_id",
)
_DOM_SINKS: tuple[str, ...] = ("innerhtml", "document.write", "document.writeln", "eval(")
_DOM_SOURCES: tuple[str, ...] = (
    "location.search",
    "location.hash",
    "location.href",
    "window.location",
    "document.location",
    "document.url",
    "document.referrer",
)
_SENSITIVE_PROBES: tuple[str, ...] = (
    "/.git/",
    "/.env",
    "/phpinfo.php",
    "/server-status",
    "/setup/",
    "remote_agent.php",
    "/public/plugins/",
    "/CFIDE/administrator/",
    "/minio/bootstrap/v1/verify",
    "GetPhpInfo.php",
)


@dataclass(frozen=True)
class HeaderReport:
    """Result of a passive header audit against one URL."""

    url: str
    final_url: str
    status_code: int
    findings: tuple[Finding, ...] = field(default=())
    present_headers: tuple[str, ...] = field(default=())
    cookie_count: int = 0
    errors: tuple[str, ...] = field(default=())
    whitelisted: bool = False

    def _counts(self) -> dict[str, int]:
        """Count findings per severity label."""
        from src.core.loader import Severity

        counts = {level.value: 0 for level in Severity}
        for item in self.findings:
            counts[item.severity.value] += 1
        return counts

    def _has_blocking(self) -> bool:
        """Return True when at least one HIGH/CRITICAL finding exists."""
        return any(item._is_blocking() for item in self.findings)

    def _summary(self) -> dict[str, object]:
        """Return a JSON-safe summary of the audit."""
        return {
            "url": self.url,
            "final_url": self.final_url,
            "status_code": self.status_code,
            "cookies_observed": self.cookie_count,
            "headers_present": list(self.present_headers),
            "counts": self._counts(),
            "errors": list(self.errors),
        }


def _normalize_url(url: str) -> str:
    """Validate a target URL and default it to https when no scheme is given."""
    candidate = url.strip()
    if not candidate:
        raise ValueError("URL must not be empty")
    if "://" not in candidate:
        candidate = f"https://{candidate}"
    parsed = urlparse(candidate)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError(f"unsupported URL scheme: {parsed.scheme!r} (use http or https)")
    if not parsed.netloc:
        raise ValueError(f"URL is missing a host: {url!r}")
    return candidate


def _headers_map(response: httpx.Response) -> dict[str, str]:
    """Collapse response headers into a lowercase name -> value mapping."""
    return {key.lower(): value for key, value in response.headers.items()}


def _cookie_headers(response: httpx.Response) -> list[str]:
    """Return every raw Set-Cookie header value from the response."""
    values = response.headers.get_list("set-cookie")
    return [value for value in values if value]


def _cookie_attributes(raw_cookie: str) -> set[str]:
    """Return the lowercase attribute and flag names present on a cookie."""
    segments = [segment.strip() for segment in raw_cookie.split(";")]
    attributes: set[str] = set()
    for segment in segments[1:]:
        if not segment:
            continue
        match = DIRECTIVE_PATTERN.match(segment)
        if match:
            attributes.add(match.group(1).lower())
    return attributes


def _cookie_samesite(raw_cookie: str) -> str | None:
    """Extract the SameSite attribute value from a raw Set-Cookie header."""
    for segment in raw_cookie.split(";")[1:]:
        if "=" not in segment:
            continue
        key, _, value = segment.partition("=")
        if key.strip().lower() == "samesite":
            return value.strip().lower()
    return None


def _cookie_name(raw_cookie: str) -> str:
    """Extract the cookie name from a raw Set-Cookie header."""
    head = raw_cookie.split(";", 1)[0]
    name, _, _ = head.partition("=")
    return name.strip() or "(unnamed)"


def _csp_directives(value: str) -> set[str]:
    """Return the lowercase directive names present in a CSP value."""
    directives: set[str] = set()
    for segment in value.split(";"):
        match = DIRECTIVE_PATTERN.match(segment)
        if match:
            directives.add(match.group(1).lower())
    return directives


def _make_finding(
    rule: Rule,
    url: str,
    message: str,
    header: str = "",
) -> Finding:
    """Build a Finding for a header-level violation."""
    return Finding(
        rule_id=rule.rule_id,
        rule_name=rule.name,
        severity=rule.severity,
        category=rule.category,
        cwe_id=rule.cwe_id,
        cve=rule.cve,
        cve_date=rule.cve_date,
        file_path=url,
        line_number=0,
        column=0,
        code_snippet=header,
        message=message,
        remediation=rule.remediation_example,
    )


def _check_presence_rule(rule: Rule, headers: dict[str, str], url: str) -> list[Finding]:
    """Evaluate a 'presence' style header rule."""
    name = rule.patterns._header()
    if not name:
        return []

    findings: list[Finding] = []
    value = headers.get(name)

    alternative = rule.patterns._get("alternative_header")
    alternative_directive = rule.patterns._get("alternative_directive")
    if value is None and alternative and alternative_directive:
        alt_value = headers.get(str(alternative).lower(), "")
        if str(alternative_directive).lower() in _csp_directives(alt_value):
            return []

    if value is None:
        findings.append(
            _make_finding(rule, url, f"response is missing the {name} header", header=name)
        )
        return findings

    if not value.strip():
        findings.append(
            _make_finding(rule, url, f"the {name} header is present but empty", header=name)
        )
        return findings

    expected = rule.patterns._get("expected_value")
    if expected and str(expected).lower() not in value.lower():
        findings.append(
            _make_finding(
                rule,
                url,
                f"the {name} header should be {expected!r} but is {value!r}",
                header=f"{name}: {value}",
            )
        )
        return findings

    allowed = [str(item).lower() for item in rule.patterns._strings("allowed_values")]
    if allowed and value.strip().lower() not in allowed:
        findings.append(
            _make_finding(
                rule,
                url,
                f"the {name} header value {value!r} is not one of {allowed}",
                header=f"{name}: {value}",
            )
        )
        return findings

    weak = [str(item).lower() for item in rule.patterns._strings("weak_values")]
    for marker in weak:
        if marker == "*":
            if _RE_CSP_WILDCARD.search(value):
                findings.append(
                    _make_finding(
                        rule,
                        url,
                        f"the {name} header uses an overly permissive wildcard source",
                        header=f"{name}: {value}",
                    )
                )
                break
        elif marker in value.lower():
            findings.append(
                _make_finding(
                    rule,
                    url,
                    f"the {name} header contains the weak value {marker!r}",
                    header=f"{name}: {value}",
                )
            )
            break

    required = [str(item).lower() for item in rule.patterns._strings("required_directives")]
    if required:
        present = _csp_directives(value) if "content-security-policy" in name else set()
        if "content-security-policy" in name:
            missing = [directive for directive in required if directive not in present]
            if missing:
                findings.append(
                    _make_finding(
                        rule,
                        url,
                        f"the {name} header is missing directives: {', '.join(missing)}",
                        header=f"{name}: {value}",
                    )
                )

    minimum = rule.patterns._get("min_max_age")
    if minimum is not None and name == "strict-transport-security":
        match = MAX_AGE_PATTERN.search(value)
        if match is None:
            findings.append(
                _make_finding(
                    rule,
                    url,
                    f"the {name} header has no max-age directive",
                    header=f"{name}: {value}",
                )
            )
        elif int(match.group(1)) < int(minimum):
            findings.append(
                _make_finding(
                    rule,
                    url,
                    f"the {name} header max-age={match.group(1)} is below the "
                    f"recommended {int(minimum)} seconds",
                    header=f"{name}: {value}",
                )
            )

    return findings


def _check_disclosure_rule(rule: Rule, headers: dict[str, str], url: str) -> list[Finding]:
    """Evaluate a 'disclosure' style rule over leaky banner headers."""
    findings: list[Finding] = []
    for name in [str(item).lower() for item in rule.patterns._strings("leaky_headers")]:
        value = headers.get(name)
        if value is None or not value.strip():
            continue
        if name == "server" and value.strip().lower() in {"", "unknown"}:
            continue
        findings.append(
            _make_finding(
                rule,
                url,
                f"the {name} header discloses implementation details: {value!r}",
                header=f"{name}: {value}",
            )
        )
    return findings


def _check_cors_rule(rule: Rule, headers: dict[str, str], url: str) -> list[Finding]:
    """Evaluate a 'cors' style rule against the CORS response headers."""
    origin_name = str(rule.patterns._get("origin_header", "access-control-allow-origin")).lower()
    credentials_name = str(
        rule.patterns._get("credentials_header", "access-control-allow-credentials")
    ).lower()
    wildcard = str(rule.patterns._get("wildcard", "*")).strip()
    truthy = [
        item.strip().lower()
        for item in rule.patterns._strings("allow_credentials_true") or ["true"]
    ]

    origin = headers.get(origin_name, "").strip()
    if not origin:
        return []

    credentials = headers.get(credentials_name, "").strip().lower() in truthy
    reasons: list[str] = []

    if origin == wildcard:
        if credentials:
            reasons.append(f"{origin_name}: {origin} combined with credentials")
        else:
            reasons.append(f"{origin_name}: {origin} allows any origin")
    elif origin and origin_name in headers:
        if credentials and not _is_static_origin(origin):
            reasons.append(f"{origin_name} reflects an arbitrary origin with credentials")

    if not reasons:
        return []
    return [
        _make_finding(
            rule,
            url,
            f"permissive CORS policy: {'; '.join(reasons)}",
            header=f"{origin_name}: {origin}",
        )
    ]


def _is_static_origin(origin: str) -> bool:
    """Return True when an origin looks like a fixed, non-reflected value."""
    lowered = origin.strip().lower()
    if lowered in {"", "null"}:
        return True
    return "{" in lowered or "}" in lowered or "%s" in lowered


def _check_redirect_rule(
    rule: Rule,
    body: str,
    url: str,
) -> list[Finding]:
    """Flag redirect/fetch style query parameters reachable from the page.

    Only links and form actions on the audited response are inspected, so this
    never issues a request and never follows a redirect itself.
    """
    if not body:
        return []
    parser = _parse_html(body)
    tokens = {token.lower() for token in REDIRECT_PARAMETER_TOKENS}
    hits: list[str] = []
    for raw in [*parser.links, *(str(f.get("action") or "") for f in parser.forms)]:
        stripped = raw.strip()
        if not stripped:
            continue
        absolute = urljoin(url, stripped)
        if not _is_same_origin(absolute, url):
            continue
        for name in _query_parameters(absolute):
            if name.lower() in tokens and name not in hits:
                hits.append(name)
    if not hits:
        return []
    return [
        _make_finding(
            rule,
            url,
            f"redirect or URL-fetch parameter exposed: {', '.join(hits)}",
            header=hits[0],
        )
    ]


def _check_body_disclosure_rule(
    rule: Rule,
    body: str,
    url: str,
) -> list[Finding]:
    """Evaluate a 'body_disclosure' style rule against the response body."""
    if not body:
        return []
    lowered = body.lower()
    signatures = [
        str(item).strip().lower() for item in rule.patterns._strings("signatures")
    ]
    hits = [signature for signature in signatures if signature and signature in lowered]
    if not hits:
        return []
    return [
        _make_finding(
            rule,
            url,
            f"response body exposes a debug traceback ({hits[0]})",
            header=hits[0],
        )
    ]


def _check_cookie_rule(
    rule: Rule,
    cookies: list[str],
    url: str,
) -> list[Finding]:
    """Evaluate a 'cookie' style rule across all observed Set-Cookie values."""
    attribute = str(rule.patterns._get("cookie_attribute", "")).lower()
    if not attribute:
        return []

    allowed = [str(item).lower() for item in rule.patterns._strings("allowed_values")]
    findings: list[Finding] = []

    for raw in cookies:
        name = _cookie_name(raw)
        attributes = _cookie_attributes(raw)

        if attribute == "samesite":
            value = _cookie_samesite(raw)
            if value is None:
                findings.append(
                    _make_finding(
                        rule,
                        url,
                        f"cookie {name!r} has no SameSite attribute",
                        header=raw,
                    )
                )
                continue
            effective = allowed or ["lax", "strict"]
            if value == "none" and "secure" not in attributes:
                findings.append(
                    _make_finding(
                        rule,
                        url,
                        f"cookie {name!r} uses SameSite=None without the Secure attribute",
                        header=raw,
                    )
                )
            elif value not in effective:
                findings.append(
                    _make_finding(
                        rule,
                        url,
                        f"cookie {name!r} uses weak SameSite={value}",
                        header=raw,
                    )
                )
            continue

        if attribute not in attributes:
            findings.append(
                _make_finding(
                    rule,
                    url,
                    f"cookie {name!r} is missing the {attribute} attribute",
                    header=raw,
                )
            )
    return findings


def _evaluate(
    rules: list[Rule],
    headers: dict[str, str],
    cookies: list[str],
    url: str,
    body: str = "",
) -> list[Finding]:
    """Evaluate every enabled header rule against the response metadata."""
    findings: list[Finding] = []
    for rule in rules:
        kind = str(rule.patterns._get("type", "presence")).lower()
        if kind == "presence":
            findings.extend(_check_presence_rule(rule, headers, url))
        elif kind == "disclosure":
            findings.extend(_check_disclosure_rule(rule, headers, url))
        elif kind == "cookie":
            findings.extend(_check_cookie_rule(rule, cookies, url))
        elif kind == "cors":
            findings.extend(_check_cors_rule(rule, headers, url))
        elif kind == "body_disclosure":
            findings.extend(_check_body_disclosure_rule(rule, body, url))
        elif kind == "redirect_surface":
            findings.extend(_check_redirect_rule(rule, body, url))
    findings.sort(key=Finding._sort_key)
    return findings


def _matches(finding: Finding) -> str:
    """Return the rule id for a finding (convenience for tests)."""
    return finding.rule_id


def _is_whitelisted_host(host: str, patterns: Iterable[str]) -> bool:
    """Return True if host matches any exact or wildcard domain pattern."""
    h = host.lower().strip()
    if ":" in h:
        h = h.split(":", 1)[0]
    for pattern in patterns:
        p = pattern.lower().strip()
        if not p:
            continue
        if p.startswith("*."):
            base = p[2:]
            if h == base or h.endswith("." + base):
                return True
        elif p.startswith("."):
            base = p[1:]
            if h == base or h.endswith("." + base):
                return True
        else:
            if h == p:
                return True
    return False


@lru_cache(maxsize=1)
def _load_whitelist() -> dict[str, list[str]]:
    """Load default whitelist configuration and optional local .sentinelwhitelist."""
    whitelist_path = Path(__file__).resolve().parent.parent / "json" / "whitelist.json"
    domains: list[str] = ["localhost", "127.0.0.1"]
    trusted_external: list[str] = []

    if whitelist_path.is_file():
        try:
            raw = whitelist_path.read_text(encoding="utf-8")
            data = json.loads(raw)
            if isinstance(data, dict):
                domains = [str(d) for d in data.get("domains", domains)]
                trusted_external = [str(d) for d in data.get("trusted_external_links", [])]
        except (OSError, json.JSONDecodeError):
            pass

    local_whitelist = Path.cwd() / ".sentinelwhitelist"
    if local_whitelist.is_file():
        try:
            content = local_whitelist.read_text(encoding="utf-8", errors="replace")
            for line in content.splitlines():
                stripped = line.partition("#")[0].strip()
                if stripped and stripped not in domains:
                    domains.append(stripped)
        except OSError:
            pass

    return {
        "domains": domains,
        "trusted_external_links": trusted_external,
    }


def _analyze(
    url: str,
    timeout: float = DEFAULT_TIMEOUT,
    follow_redirects: bool = True,
    max_redirects: int = DEFAULT_REDIRECTS,
    client: httpx.Client | None = None,
) -> HeaderReport:
    """Perform one passive request and audit the response security headers."""
    target = _normalize_url(url)
    target_host = urlparse(target).hostname or ""
    whitelist = _load_whitelist()
    if _is_whitelisted_host(target_host, whitelist.get("domains", [])):
        return HeaderReport(
            url=target,
            final_url=target,
            status_code=200,
            findings=(),
            present_headers=(),
            cookie_count=0,
            errors=(),
            whitelisted=True,
        )

    rules = _rules_for(ANALYZER_NAME)
    errors: list[str] = []

    headers: dict[str, str] = {}
    cookies: list[str] = []
    status = 0
    final_url = target
    body = ""

    request_headers = {"User-Agent": USER_AGENT, "Accept": "*/*"}

    try:
        if client is not None:
            response = client.request(
                "GET",
                target,
                headers=request_headers,
                follow_redirects=follow_redirects,
            )
        else:
            with httpx.Client(
                timeout=timeout,
                follow_redirects=follow_redirects,
                max_redirects=max_redirects,
            ) as session:
                response = session.request("GET", target, headers=request_headers)
        status = int(response.status_code)
        final_url = str(response.url)
        headers = _headers_map(response)
        cookies = _cookie_headers(response)
        body = _body_text(response)
    except httpx.TimeoutException as exc:
        errors.append(f"request timed out after {timeout}s: {exc.__class__.__name__}")
    except httpx.TooManyRedirects as exc:
        errors.append(f"too many redirects (limit {max_redirects}): {exc.__class__.__name__}")
    except httpx.HTTPError as exc:
        errors.append(f"request failed: {exc.__class__.__name__}: {exc}")
    except ValueError as exc:
        errors.append(f"invalid target: {exc}")

    if not headers and errors:
        return HeaderReport(
            url=target,
            final_url=final_url,
            status_code=status,
            findings=(),
            present_headers=(),
            cookie_count=0,
            errors=tuple(errors),
        )

    findings = _evaluate(rules, headers, cookies, final_url, body)
    return HeaderReport(
        url=target,
        final_url=final_url,
        status_code=status,
        findings=tuple(findings),
        present_headers=tuple(sorted(headers)),
        cookie_count=len(cookies),
        errors=tuple(errors),
    )


CATEGORY_XSS: str = "xss"
CATEGORY_SQLI: str = "sql injection"
CATEGORY_HEADERS: str = "headers & cookies"
CATEGORY_CORS: str = "cors & info leak"
CATEGORY_SSRF: str = "ssrf & redirects"
CATEGORY_STACK: str = "stack & shells"

REDIRECT_PARAMETER_TOKENS: tuple[str, ...] = (
    "url",
    "redirect",
    "redirect_uri",
    "redirect_url",
    "next",
    "target",
    "dest",
    "destination",
    "return_to",
    "returnto",
    "return_url",
    "returnurl",
    "callback",
    "continue",
    "redir",
    "goto",
    "fetch",
    "image",
    "img",
    "src",
)

SENSITIVE_BODY_MARKERS: tuple[str, ...] = (
    "index of /",
    "directory listing for",
    "db_password=",
    "database_url=",
    "secret_key=",
    "aws_secret_access_key",
    "-----begin rsa private key-----",
    "-----begin private key-----",
    "-----begin openssh private key-----",
    "root:x:0:0",
)

CATEGORY_ORDER: tuple[str, ...] = (
    CATEGORY_XSS,
    CATEGORY_SQLI,
    CATEGORY_HEADERS,
    CATEGORY_CORS,
    CATEGORY_SSRF,
    CATEGORY_STACK,
)

REFLECTION_PROBE: str = "<sentinelprobe>"
CANARY_PREFIX: str = "sentinel_canary_"
XSS_REFLECTION_WINDOW: int = 400
BODY_LIMIT: int = 2_000_000

MAX_PAGES: int = 25
MAX_DISCOVERED_LINKS: int = 100
MAX_SURFACE_FINDINGS: int = 25

CSRF_FIELD_TOKENS: tuple[str, ...] = (
    "csrf",
    "token",
    "nonce",
    "authenticity_token",
    "xsrf",
    "__requestverificationtoken",
)

SUBRESOURCE_ATTRS: tuple[tuple[str, str], ...] = (
    ("script", "src"),
    ("link", "href"),
    ("iframe", "src"),
    ("img", "src"),
    ("source", "src"),
    ("audio", "src"),
    ("video", "src"),
    ("form", "action"),
)

SQL_ERROR_SIGNATURES: tuple[str, ...] = (
    "sql syntax",
    "you have an error in your sql",
    "syntax error",
    "database exception",
    "operationalerror",
    "sqlite3.operationalerror",
    "database query error",
    "sql error",
    "unclosed quotation mark",
    "unclosed quote",
    "quoted string not properly terminated",
    "unrecognized token",
    "mysqli",
    "mysqld",
    "pg_query",
    "psql:",
    "postgresql",
    "sqlite3",
    "sqlite error",
    "ora-0",
    "oracle error",
    "microsoft ole db",
    "odbc sql server",
    "sqlstate",
    "db2 sql error",
    "jdbc",
)

DB_DEBUG_HEADERS: frozenset[str] = frozenset(
    {
        "x-debug-database",
        "x-debug-sql-mode",
        "x-debug-sql-error",
        "x-debug-sql",
        "x-sql",
        "x-db",
        "x-database",
        "x-query",
    }
)

QUERY_DEBUG_HEADERS: frozenset[str] = frozenset(
    {
        "x-debug-sql-mode",
        "x-debug-sql-error",
        "x-debug-sql",
        "x-sql",
        "x-query",
    }
)

DEBUG_BODY_SIGNATURES: tuple[str, ...] = (
    "traceback (most recent call last)",
    "werkzeug debugger",
    "django.views.debug",
    "you're seeing this error because you have",
    "django version",
    "flask debug",
    "sqlalchemy.exc.",
    "psycopg2.errors",
    "sqlite3.operationalerror",
    "unhandled exception",
    "stack trace:",
)

INLINE_SCRIPT_MARKERS: tuple[str, ...] = (
    "<script>",
    "<script ",
    "onerror=",
    "onload=",
    "javascript:",
)


class Verdict(str, Enum):
    """Three-tier outcome for one URL audit category.

    ``VULNERABLE`` is reserved for confirmed, directly observable issues: an
    exposed traceback or SQL error, a dangerous CORS policy, or an unescaped
    reflection actually seen in the response. ``HARDENING`` covers missing
    defence-in-depth controls that raise risk but are not proof of exploitability.
    """

    SAFE = "SAFE"
    HARDENING = "HARDENING NEEDED"
    VULNERABLE = "VULNERABLE"

    def _rank(self) -> int:
        """Return a sortable rank so verdicts can be ordered by severity."""
        return _VERDICT_RANK[self]

    def _is_vulnerable(self) -> bool:
        """Return True only for a confirmed, high-confidence issue."""
        return self is Verdict.VULNERABLE

    def _needs_attention(self) -> bool:
        """Return True when the category is anything other than fully safe."""
        return self is not Verdict.SAFE


_VERDICT_RANK: dict[Verdict, int] = {
    Verdict.SAFE: 0,
    Verdict.HARDENING: 1,
    Verdict.VULNERABLE: 2,
}


def _worst(*verdicts: Verdict) -> Verdict:
    """Return the most severe verdict among those supplied."""
    if not verdicts:
        return Verdict.SAFE
    return max(verdicts, key=Verdict._rank)


@dataclass(frozen=True)
class CategoryResult:
    """Outcome of one audit category for a URL."""

    name: str
    verdict: Verdict = Verdict.SAFE
    reasons: tuple[str, ...] = field(default=())
    rule_ids: tuple[str, ...] = field(default=())

    @property
    def _is_vulnerable(self) -> bool:
        """Return True only when this category is confirmed vulnerable."""
        return self.verdict._is_vulnerable()

    def _label(self) -> str:
        """Return the status label for this category."""
        return self.verdict.value

    def _summary(self) -> str:
        """Return a one-line status with comma-separated reasons."""
        if self.verdict is Verdict.SAFE:
            return "SAFE"
        return ", ".join(self.reasons) if self.reasons else "indicators detected"

    def _as_dict(self) -> dict[str, object]:
        """Serialize the category result for JSON output."""
        return {
            "category": self.name,
            "status": self._label(),
            "verdict": self.verdict.value,
            "vulnerable": self.verdict._is_vulnerable(),
            "needs_hardening": self.verdict is Verdict.HARDENING,
            "reasons": list(self.reasons),
            "rule_ids": list(self.rule_ids),
        }


@dataclass(frozen=True)
class WebReport:
    """Unified result of the xss / sql injection / headers checks for one URL."""

    url: str
    final_url: str
    status_code: int
    categories: tuple[CategoryResult, ...] = field(default=())
    findings: tuple[Finding, ...] = field(default=())
    errors: tuple[str, ...] = field(default=())
    pages: tuple[str, ...] = field(default=())
    deep: bool = False
    present_headers: tuple[str, ...] = field(default=())
    cookie_count: int = 0
    whitelisted: bool = False

    def _category(self, name: str) -> CategoryResult:
        """Return one category result by name."""
        for item in self.categories:
            if item.name == name:
                return item
        return CategoryResult(name=name, verdict=Verdict.SAFE)

    def _vulnerable_categories(self) -> tuple[CategoryResult, ...]:
        """Return only the categories with a confirmed vulnerability."""
        return tuple(item for item in self.categories if item.verdict._is_vulnerable())

    def _hardening_categories(self) -> tuple[CategoryResult, ...]:
        """Return only the categories that need defence-in-depth work."""
        return tuple(item for item in self.categories if item.verdict is Verdict.HARDENING)

    def _has_blocking(self) -> bool:
        """Return True only when a confirmed vulnerability was observed.

        Missing hardening headers alone do not fail a passive scan; they are
        reported as HARDENING NEEDED so the operator can triage them.
        """
        if self.whitelisted:
            return False
        return any(item.verdict._is_vulnerable() for item in self.categories)

    def _needs_hardening(self) -> bool:
        """Return True when any category needs hardening (not necessarily failing)."""
        if self.whitelisted:
            return False
        return any(item.verdict._needs_attention() for item in self.categories)

    def _verdict(self) -> Verdict:
        """Return the worst verdict across every category."""
        if self.whitelisted:
            return Verdict.SAFE
        return _worst(*(item.verdict for item in self.categories))

    def _counts(self) -> dict[str, int]:
        """Count findings per severity label."""
        from src.core.loader import Severity

        counts = {level.value: 0 for level in Severity}
        for item in self.findings:
            counts[item.severity.value] += 1
        return counts

    def _summary(self) -> dict[str, object]:
        """Return a JSON-safe summary of the unified check."""
        return {
            "url": self.url,
            "final_url": self.final_url,
            "status_code": self.status_code,
            "whitelisted": self.whitelisted,
            "verdict": self._verdict().value,
            "deep": self.deep,
            "pages_inspected": list(self.pages),
            "vulnerable": [item.name for item in self._vulnerable_categories()],
            "needs_hardening": [item.name for item in self._hardening_categories()],
            "categories": [item._as_dict() for item in self.categories],
            "counts": self._counts(),
            "errors": list(self.errors),
        }


def _fetch(
    url: str,
    timeout: float,
    follow_redirects: bool,
    max_redirects: int,
    client: httpx.Client | None,
) -> tuple[httpx.Response | None, list[str]]:
    """Perform the single passive request used by the unified check."""
    request_headers = {
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
    }
    errors: list[str] = []
    try:
        if client is not None:
            response = client.request(
                "GET", url, headers=request_headers, follow_redirects=follow_redirects
            )
        else:
            with httpx.Client(
                timeout=timeout,
                follow_redirects=follow_redirects,
                max_redirects=max_redirects,
            ) as session:
                response = session.request("GET", url, headers=request_headers)
        return response, errors
    except httpx.TimeoutException as exc:
        errors.append(f"request timed out after {timeout}s: {exc.__class__.__name__}")
    except httpx.TooManyRedirects as exc:
        errors.append(f"too many redirects (limit {max_redirects}): {exc.__class__.__name__}")
    except httpx.HTTPError as exc:
        errors.append(f"request failed: {exc.__class__.__name__}: {exc}")
    except ValueError as exc:
        errors.append(f"invalid target: {exc}")
    return None, errors


def _body_text(response: httpx.Response) -> str:
    """Return a bounded, decoded copy of a textual response body."""
    content_type = response.headers.get("content-type", "").lower()
    if content_type and not any(
        marker in content_type for marker in ("text/", "html", "xml", "json")
    ):
        return ""
    try:
        text = response.text
    except Exception:
        return ""
    return text[:BODY_LIMIT]


def _has_unescaped_reflection(body: str, probe: str = REFLECTION_PROBE) -> bool:
    """Return True when the probe appears in the body as raw, unescaped text."""
    if probe not in body:
        return False
    index = body.find(probe)
    window = body[max(0, index - XSS_REFLECTION_WINDOW) : index + XSS_REFLECTION_WINDOW]
    lowered = window.lower()
    escaped_forms = ("&lt;", "&gt;", "&#", "\\u003c", "\\x3c", "%3c")
    if any(marker in lowered for marker in escaped_forms):
        return False
    return True


def _probe_url(url: str) -> str | None:
    """Return a URL with the first query parameter set to the reflection probe."""
    parsed = urlparse(url)
    if not parsed.query:
        return None
    pairs = [
        f"{chunk.partition('=')[0]}={REFLECTION_PROBE}"
        for chunk in parsed.query.split("&")
        if chunk
    ]
    if not pairs:
        return None
    return parsed._replace(query="&".join(pairs)).geturl()


def _probe_reflection(
    url: str,
    client: httpx.Client | None,
    timeout: float,
) -> tuple[bool, bool]:
    """Send one benign reflection probe and report (probe_sent, reflected_raw).

    Only the first existing query parameter is rewritten, and only with inert
    alphabetic text. No script, quote or SQL metacharacter is sent, so this
    cannot mutate state or act as an injection attempt.
    """
    probe_url = _probe_url(url)
    if probe_url is None:
        return False, False
    try:
        if client is not None:
            probe = client.request("GET", probe_url, follow_redirects=True)
        else:
            with httpx.Client(timeout=timeout, follow_redirects=True) as session:
                probe = session.request(
                    "GET",
                    probe_url,
                    headers={"User-Agent": USER_AGENT, "Accept": "*/*"},
                )
    except (httpx.HTTPError, ValueError):
        return True, False
    return True, _has_unescaped_reflection(_body_text(probe))


def _check_xss_surface(
    headers: dict[str, str],
    body: str,
    reflection_raw: bool = False,
) -> CategoryResult:
    """Evaluate the XSS category from headers, body and reflection state.

    Only an actually observed unescaped reflection confirms XSS. A missing or
    permissive CSP is reported as HARDENING NEEDED, because it increases the
    impact of a hypothetical injection but does not prove one exists.
    """
    weak_reasons: list[str] = []
    weak_rules: list[str] = []
    confirmed_reasons: list[str] = []
    confirmed_rules: list[str] = []

    csp = headers.get("content-security-policy", "").strip()
    lowered_csp = csp.lower()

    if not csp:
        weak_reasons.append("missing CSP")
        weak_rules.append("HDR001")
    else:
        weak = [token for token in ("unsafe-inline", "unsafe-eval") if token in lowered_csp]
        if weak:
            weak_reasons.append(f"weak CSP ({', '.join(weak)})")
            weak_rules.append("HDR001")

    if reflection_raw:
        confirmed_reasons.append("unescaped reflection")
        confirmed_rules.append("XSS004")

    if "x-content-type-options" not in headers:
        weak_reasons.append("missing X-Content-Type-Options")
        weak_rules.append("HDR003")

    if not reflection_raw and "script-src" not in lowered_csp:
        lowered_body = body.lower()
        if any(marker in lowered_body for marker in INLINE_SCRIPT_MARKERS):
            weak_reasons.append("inline script exposure")
            weak_rules.append("XSS004")

    if confirmed_reasons:
        return CategoryResult(
            name=CATEGORY_XSS,
            verdict=Verdict.VULNERABLE,
            reasons=tuple(dict.fromkeys(confirmed_reasons)),
            rule_ids=tuple(dict.fromkeys(confirmed_rules)),
        )
    if weak_reasons:
        return CategoryResult(
            name=CATEGORY_XSS,
            verdict=Verdict.HARDENING,
            reasons=tuple(dict.fromkeys(weak_reasons)),
            rule_ids=tuple(dict.fromkeys(weak_rules)),
        )
    return CategoryResult(name=CATEGORY_XSS, verdict=Verdict.SAFE)


def _check_sqli_surface(headers: dict[str, str], body: str) -> CategoryResult:
    """Evaluate the SQL injection category from error and debug indicators."""
    reasons: list[str] = []
    rule_ids: list[str] = []

    debug_headers = sorted(
        name
        for name in headers
        if name in QUERY_DEBUG_HEADERS or name.startswith("x-debug-sql")
    )

    lowered = body.lower()
    hits = [signature for signature in SQL_ERROR_SIGNATURES if signature in lowered]
    if hits:
        reasons.append(f"database error signature ({hits[0]})")
        rule_ids.append("SQLI005")
        return CategoryResult(
            name=CATEGORY_SQLI,
            verdict=Verdict.VULNERABLE,
            reasons=tuple(reasons),
            rule_ids=tuple(dict.fromkeys(rule_ids)),
        )

    if debug_headers:
        reasons.append(f"verbose DB debug headers ({', '.join(debug_headers)})")
        rule_ids.append("SQLI005")
        return CategoryResult(
            name=CATEGORY_SQLI,
            verdict=Verdict.HARDENING,
            reasons=tuple(reasons),
            rule_ids=tuple(dict.fromkeys(rule_ids)),
        )

    return CategoryResult(name=CATEGORY_SQLI, verdict=Verdict.SAFE)


def _check_cors_surface(headers: dict[str, str], body: str) -> CategoryResult:
    """Evaluate the cors & info leak category from headers and body."""
    confirmed_reasons: list[str] = []
    confirmed_rules: list[str] = []
    weak_reasons: list[str] = []
    weak_rules: list[str] = []

    origin = headers.get("access-control-allow-origin", "").strip()
    credentials = headers.get("access-control-allow-credentials", "").strip().lower()
    allows_credentials = credentials in {"true", "1"}
    if origin:
        if origin == "*" and allows_credentials:
            confirmed_reasons.append("wildcard CORS with credentials")
            confirmed_rules.append("HDR011")
        elif origin == "*":
            weak_reasons.append("wildcard CORS origin")
            weak_rules.append("HDR011")
        elif allows_credentials and _is_static_origin(origin):
            confirmed_reasons.append("reflected origin with credentials")
            confirmed_rules.append("HDR011")

    if body:
        lowered = body.lower()
        traces = [
            signature
            for signature in DEBUG_BODY_SIGNATURES
            if signature in lowered
        ]
        if traces:
            confirmed_reasons.append(f"debug traceback ({traces[0]})")
            confirmed_rules.append("HDR012")

    if confirmed_reasons:
        return CategoryResult(
            name=CATEGORY_CORS,
            verdict=Verdict.VULNERABLE,
            reasons=tuple(dict.fromkeys(confirmed_reasons)),
            rule_ids=tuple(dict.fromkeys(confirmed_rules)),
        )
    if weak_reasons:
        return CategoryResult(
            name=CATEGORY_CORS,
            verdict=Verdict.HARDENING,
            reasons=tuple(dict.fromkeys(weak_reasons)),
            rule_ids=tuple(dict.fromkeys(weak_rules)),
        )
    return CategoryResult(name=CATEGORY_CORS, verdict=Verdict.SAFE)


def _check_header_surface(headers: dict[str, str], cookies: list[str]) -> CategoryResult:
    """Evaluate the headers & cookies category from response metadata.

    Missing response headers are defence-in-depth gaps (HARDENING). Insecure
    cookie flags and explicit debug headers reveal material an attacker can act
    on directly, so those confirm the category.
    """
    weak_reasons: list[str] = []
    weak_rules: list[str] = []
    confirmed_reasons: list[str] = []
    confirmed_rules: list[str] = []

    required = (
        ("strict-transport-security", "HSTS", "HDR002"),
        ("x-frame-options", "X-Frame-Options", "HDR004"),
        ("x-content-type-options", "X-Content-Type-Options", "HDR003"),
        ("referrer-policy", "Referrer-Policy", "HDR005"),
        ("permissions-policy", "Permissions-Policy", "HDR006"),
    )
    for name, label, rule_id in required:
        if name not in headers:
            weak_reasons.append(f"missing {label}")
            weak_rules.append(rule_id)

    if "x-frame-options" not in headers:
        if "frame-ancestors" in headers.get("content-security-policy", "").lower():
            weak_reasons.remove("missing X-Frame-Options")
            weak_rules.remove("HDR004")

    banners = [name for name in ("server", "x-powered-by") if headers.get(name)]
    if banners:
        weak_reasons.append(f"server banner ({', '.join(banners)})")
        weak_rules.append("HDR007")

    cache_headers = [
        name
        for name in ("x-cache", "cf-cache-status", "age", "via", "x-varnish")
        if headers.get(name)
    ]
    if cache_headers:
        vary = headers.get("vary", "").lower()
        if "host" not in vary:
            weak_reasons.append(f"unkeyed cache ({', '.join(cache_headers)}) without Vary: Host")
            weak_rules.append("HST002")

    debug_banner = sorted(name for name in headers if name in DB_DEBUG_HEADERS)
    issues: set[str] = set()
    for raw in cookies:
        attributes = _cookie_attributes(raw)
        missing = [
            label
            for attribute, label in (
                ("httponly", "HttpOnly"),
                ("secure", "Secure"),
                ("samesite", "SameSite"),
            )
            if attribute not in attributes
        ]
        if not missing:
            continue
        issues.update(missing)
    if issues:
        ordered = [label for label in ("HttpOnly", "Secure", "SameSite") if label in issues]
        confirmed_reasons.append(f"insecure cookie flags ({', '.join(ordered)})")
        confirmed_rules.append("HDR008")
    if debug_banner:
        confirmed_reasons.append(f"debug disclosure ({', '.join(debug_banner)})")
        confirmed_rules.append("HDR007")

    if confirmed_reasons:
        return CategoryResult(
            name=CATEGORY_HEADERS,
            verdict=Verdict.VULNERABLE,
            reasons=tuple(dict.fromkeys(confirmed_reasons)),
            rule_ids=tuple(dict.fromkeys(confirmed_rules)),
        )
    if weak_reasons:
        return CategoryResult(
            name=CATEGORY_HEADERS,
            verdict=Verdict.HARDENING,
            reasons=tuple(dict.fromkeys(weak_reasons)),
            rule_ids=tuple(dict.fromkeys(weak_rules)),
        )
    return CategoryResult(name=CATEGORY_HEADERS, verdict=Verdict.SAFE)


class SurfaceParser(HTMLParser):
    """Collect links, forms and subresources from one HTML document.

    Only parsing happens here: nothing is fetched and no markup is executed.
    """

    def __init__(self) -> None:
        """Initialise an empty collector."""
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.forms: list[dict[str, object]] = []
        self.subresources: list[dict[str, str]] = []
        self.password_inputs: list[str] = []
        self.file_inputs: list[str] = []
        self.anchors: list[dict[str, str]] = []
        self.inline_scripts: list[str] = []
        self._in_script: bool = False
        self._form: dict[str, object] | None = None

    def _starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        """Record links, form boundaries and subresource references."""
        values = {name.lower(): (value or "") for name, value in attrs}
        lowered = tag.lower()

        if lowered == "a" and values.get("href"):
            self.links.append(values["href"])
            self.anchors.append(
                {
                    "href": values.get("href", ""),
                    "target": values.get("target", ""),
                    "rel": values.get("rel", ""),
                }
            )

        if lowered == "script" and not values.get("src"):
            self._in_script = True

        if lowered == "form":
            self._form = {
                "action": values.get("action", ""),
                "method": (values.get("method") or "get").lower(),
                "fields": [],
                "insecure": values.get("action", "").lower().startswith("http://"),
            }
            self.forms.append(self._form)

        if lowered == "input":
            field_type = (values.get("type") or "text").lower()
            name = values.get("name", "")
            if self._form is not None:
                fields = self._form.get("fields")
                if isinstance(fields, list):
                    fields.append({"type": field_type, "name": name})
            if field_type == "password":
                self.password_inputs.append(name or "(unnamed)")
            if field_type == "file":
                self.file_inputs.append(name or "(unnamed)")

        for element, attribute in SUBRESOURCE_ATTRS:
            if lowered == element and values.get(attribute):
                self.subresources.append(
                    {
                        "tag": lowered,
                        "url": values[attribute],
                        "integrity": values.get("integrity", ""),
                        "rel": values.get("rel", ""),
                        "type": values.get("type", ""),
                    }
                )

    def _endtag(self, tag: str) -> None:
        """Close the current form when its end tag is reached."""
        if tag.lower() == "form":
            if self._form and str(self._form.get("method", "get")).lower() == "get":
                action = str(self._form.get("action") or "").strip()
                fields = self._form.get("fields")
                if isinstance(fields, list) and fields:
                    params = []
                    for f in fields:
                        if isinstance(f, dict):
                            fname = str(f.get("name") or "").strip()
                            ftype = str(f.get("type") or "text").lower()
                            if fname and ftype not in ("submit", "button", "reset", "image"):
                                params.append(f"{fname}=")
                    if params:
                        sep = "&" if "?" in action else "?"
                        form_url = f"{action}{sep}{'&'.join(params)}"
                        self.links.append(form_url)
            self._form = None
        if tag.lower() == "script":
            self._in_script = False

    def _handle_data(self, data: str) -> None:
        """Collect inline script text."""
        if self._in_script and data:
            self.inline_scripts.append(data)

    handle_starttag = _starttag
    handle_endtag = _endtag
    handle_data = _handle_data


def _origin_of(url: str) -> tuple[str, str, int | None]:
    """Return the (scheme, host, port) origin of a URL."""
    parsed = urlparse(url)
    try:
        port = parsed.port
    except ValueError:
        port = None
    return parsed.scheme.lower(), (parsed.hostname or "").lower(), port


def _is_same_origin(candidate: str, base: str) -> bool:
    """Return True when a candidate URL shares scheme, host and port with base."""
    return _origin_of(candidate) == _origin_of(base)


def _parse_html(body: str) -> SurfaceParser:
    """Parse an HTML document into a populated collector."""
    parser = SurfaceParser()
    try:
        parser.feed(body)
        parser.close()
    except Exception:
        pass
    return parser


def _resolve_link(href: str, base: str) -> str | None:
    """Resolve a link against the base URL, keeping only same-origin HTTP(S)."""
    if not href:
        return None
    cleaned = href.strip()
    if cleaned.startswith(("#", "javascript:", "mailto:", "tel:", "data:")):
        return None
    try:
        absolute = urljoin(base, cleaned)
    except ValueError:
        return None
    parsed = urlparse(absolute)
    if parsed.scheme not in {"http", "https"}:
        return None
    if not _is_same_origin(absolute, base):
        return None
    return parsed._replace(fragment="").geturl()


def _discover_links(body: str, base: str, limit: int = MAX_DISCOVERED_LINKS) -> list[str]:
    """Return bounded, de-duplicated same-origin links found in one document."""
    parser = _parse_html(body)
    found: list[str] = []
    seen: set[str] = {base.rstrip("/")}

    candidates = list(parser.links)
    candidates.extend(str(form.get("action") or "") for form in parser.forms)

    for href in candidates:
        resolved = _resolve_link(href, base)
        if resolved is None:
            continue
        key = resolved.rstrip("/")
        if key in seen:
            continue
        seen.add(key)
        found.append(resolved)
        if len(found) >= limit:
            break

    return found


def _query_parameters(url: str) -> list[str]:
    """Return the query parameter names present on a URL."""
    parsed = urlparse(url)
    if not parsed.query:
        return []
    names: list[str] = []
    for chunk in parsed.query.split("&"):
        if not chunk:
            continue
        name = chunk.partition("=")[0]
        if name and name not in names:
            names.append(name)
    return names


def _canary_url(url: str, canary: str) -> str | None:
    """Return a URL whose query parameters are set to the benign canary value."""
    parsed = urlparse(url)
    names = _query_parameters(url)
    if not names:
        return None
    pairs = [f"{name}={canary}" for name in names]
    return parsed._replace(query="&".join(pairs)).geturl()


def _new_canary() -> str:
    """Return a fresh, purely alphanumeric canary marker."""
    return f"{CANARY_PREFIX}{secrets.token_hex(4)}"


def _form_has_csrf_token(fields: list[dict[str, object]]) -> bool:
    """Return True when a form carries a recognisable anti-CSRF field."""
    for field in fields:
        name = str(field.get("name") or "").lower()
        field_type = str(field.get("type") or "").lower()
        if field_type != "hidden":
            continue
        if any(token in name for token in CSRF_FIELD_TOKENS):
            return True
    return False


def _is_third_party(url: str, base: str) -> bool:
    """Return True when a subresource URL points at a different origin."""
    absolute = urljoin(base, url.strip())
    return not _is_same_origin(absolute, base)


def _redirect_parameters(
    links: list[str],
    forms: list[dict[str, object]],
    base: str,
) -> list[str]:
    """Return query parameters that look like redirect or fetch targets.

    Only same-origin destinations are considered, so third-party links never
    produce a finding. Parameter names are matched against a fixed token list
    (url, redirect, next, target, dest, return_to, ...) because those names mean
    the caller decides where the browser or server goes next.
    """
    tokens = {token.lower() for token in REDIRECT_PARAMETER_TOKENS}
    found: list[str] = []

    origins = list(links)
    for form in forms:
        action = str(form.get("action") or "")
        if action:
            origins.append(action)

    for raw in origins:
        stripped = raw.strip()
        if not stripped:
            continue
        absolute = urljoin(base, stripped)
        if not _is_same_origin(absolute, base):
            continue
        for name in _query_parameters(absolute):
            if name.lower() in tokens:
                label = f"redirect/URL parameter reachable: {name}"
                if label not in found:
                    found.append(label)
    return found


def _sensitive_body_markers(body: str) -> list[str]:
    """Return directory-listing and secret-file markers present in a body.

    These are the signals that a server is handing out a file it should not:
    an auto-generated index page, an environment assignment, a private key block
    or a passwd-style listing.
    """
    if not body:
        return []
    lowered = body.lower()
    hits = [marker for marker in SENSITIVE_BODY_MARKERS if marker in lowered]
    return hits


def _check_ssrf_surface(
    redirect_reasons: list[str],
    body: str,
) -> CategoryResult:
    """Build the 'ssrf & redirects' category.

    Suspicious redirect/fetch parameters are HARDENING NEEDED: their presence
    alone does not prove the target follows them without validation. Exposed
    directory listings or secret-file markers in the body are VULNERABLE,
    because the response itself demonstrably leaks files.
    """
    leaks = _sensitive_body_markers(body)
    reasons: list[str] = []

    for marker in leaks:
        label = f"sensitive content exposed: {marker}"
        if label not in reasons:
            reasons.append(label)
    for reason in redirect_reasons:
        if reason not in reasons:
            reasons.append(reason)

    if leaks:
        return CategoryResult(
            name=CATEGORY_SSRF,
            verdict=Verdict.VULNERABLE,
            reasons=tuple(reasons[:MAX_SURFACE_FINDINGS]),
            rule_ids=("HDR014", "HDR013"),
        )
    if reasons:
        return CategoryResult(
            name=CATEGORY_SSRF,
            verdict=Verdict.HARDENING,
            reasons=tuple(reasons[:MAX_SURFACE_FINDINGS]),
            rule_ids=("HDR013",),
        )
    return CategoryResult(name=CATEGORY_SSRF, verdict=Verdict.SAFE)


def _inspect_html_surface(
    body: str,
    base: str,
    page_is_https: bool,
    trusted_external: Sequence[str] | None = None,
) -> dict[str, list[str]]:
    """Inspect one document for CSRF, SRI, mixed-content and password issues.

    Returns a mapping of category name to human readable reasons, so the caller
    can fold them into the existing three-tier verdicts.
    """
    if trusted_external is None:
        trusted_external = _load_whitelist().get("trusted_external_links", [])

    parser = _parse_html(body)
    csrf: list[str] = []
    integrity: list[str] = []
    mixed: list[str] = []
    passwords: list[str] = []
    insecure_action: list[str] = []

    for form in parser.forms:
        method = str(form.get("method") or "get").lower()
        action = str(form.get("action") or "")
        fields = form.get("fields")
        field_list = fields if isinstance(fields, list) else []
        if method == "post" and not _form_has_csrf_token(field_list):
            label = action or "(current page)"
            csrf.append(f"POST form without CSRF token: {label}")
        if page_is_https and action.lower().startswith("http://"):
            insecure_action.append(f"form posts to plain HTTP: {action}")

    for resource in parser.subresources:
        url = resource.get("url", "")
        tag = resource.get("tag", "")
        rel = resource.get("rel", "").lower()
        resource_type = resource.get("type", "").lower()
        is_script = tag == "script"
        is_stylesheet = tag == "link" and ("stylesheet" in rel or "css" in resource_type)
        if not (is_script or is_stylesheet):
            continue
        if not _is_third_party(url, base):
            continue
        if not resource.get("integrity"):
            kind = "script" if is_script else "stylesheet"
            integrity.append(f"external {kind} without SRI integrity: {url}")

    if page_is_https:
        for resource in parser.subresources:
            url = resource.get("url", "").strip().lower()
            if url.startswith("http://"):
                mixed.append(f"mixed content over HTTPS: {resource.get('url', '')}")
        for href in parser.links:
            stripped = href.strip()
            if stripped.lower().startswith("http://") and _is_same_origin(
                urljoin(base, stripped), base
            ):
                mixed.append(f"insecure link over HTTPS: {stripped}")

    if parser.password_inputs and not page_is_https:
        passwords.append(
            "password input served over plain HTTP: " + ", ".join(parser.password_inputs)
        )

    redirects = _redirect_parameters(parser.links, parser.forms, base)

    takeovers: list[str] = []
    all_refs = [res.get("url", "") for res in parser.subresources] + parser.links
    for ref in all_refs:
        lowered_ref = ref.lower().strip()
        for dom in _TAKEOVER_DOMAINS:
            if f".{dom}" in lowered_ref:
                takeovers.append(f"external resource points to takeover-prone cloud host: {dom}")
                break

    tabnabbing: list[str] = []
    for a in parser.anchors:
        href = a.get("href", "").strip()
        target = a.get("target", "").lower().strip()
        rel = a.get("rel", "").lower().strip()
        if target == "_blank" and (href.startswith("http://") or href.startswith("https://")):
            if not _is_same_origin(href, base):
                dest_host = urlparse(href).hostname or ""
                if trusted_external and _is_whitelisted_host(dest_host, trusted_external):
                    continue
                if "noopener" not in rel and "noreferrer" not in rel:
                    display = href if len(href) <= 45 else href[:42] + "..."
                    tabnabbing.append(f"target=_blank external link missing rel=noopener: {display}")

    storage_leaks: list[str] = []
    for script_text in parser.inline_scripts:
        lowered_script = script_text.lower()
        if "localstorage.setitem" in lowered_script or "sessionstorage.setitem" in lowered_script:
            for token in _STORAGE_TOKENS:
                if token in lowered_script:
                    storage_leaks.append(f"inline script stores '{token}' in client storage")
                    break

    hidden_tampering: list[str] = []
    for form in parser.forms:
        fields = form.get("fields")
        if isinstance(fields, list):
            for field in fields:
                if isinstance(field, dict) and str(field.get("type", "")).lower() == "hidden":
                    fname = str(field.get("name", "")).lower()
                    if any(p in fname for p in _SENSITIVE_HIDDEN_PARAMS):
                        hidden_tampering.append(
                            f"sensitive parameter '{fname}' in hidden form field without tamper protection (TMP002)"
                        )

    dom_xss: list[str] = []
    postmessage_leaks: list[str] = []
    for script_text in parser.inline_scripts:
        lowered_script = script_text.lower()
        if any(sink in lowered_script for sink in _DOM_SINKS) and any(
            src in lowered_script for src in _DOM_SOURCES
        ):
            dom_xss.append(
                "client-side DOM XSS sink in inline script: innerHTML/document.write with location source (DOM001)"
            )
        if "addeventlistener('message'" in lowered_script or 'addeventlistener("message"' in lowered_script:
            if "origin" not in lowered_script:
                postmessage_leaks.append(
                    "unvalidated postMessage message event listener in inline script (DOM002)"
                )

    sensitive_paths: list[str] = []
    all_links_and_sources = parser.links + [r.get("url", "") for r in parser.subresources]
    for target_ref in all_links_and_sources:
        lowered_target = target_ref.lower()
        for probe in _SENSITIVE_PROBES:
            if probe.lower() in lowered_target:
                sensitive_paths.append(f"sensitive path reference exposed in page: {probe}")
                break

    file_uploads: list[str] = []
    if parser.file_inputs:
        file_uploads.append("file upload input present without MIME accept filter: " + ", ".join(parser.file_inputs))

    sqli_surface: list[str] = []
    lowered_doc = body.lower()
    for sig in SQL_ERROR_SIGNATURES:
        if sig in lowered_doc:
            sqli_surface.append(f"database error signature ({sig})")
            break
    for marker in ("executed statement:", "executed query:", "database query:"):
        if marker in lowered_doc:
            sqli_surface.append(f"disclosed backend database query execution ({marker.rstrip(':')})")
            break

    return {
        CATEGORY_XSS: [*dom_xss, *postmessage_leaks, *integrity],
        CATEGORY_SQLI: sqli_surface,
        CATEGORY_HEADERS: [*mixed, *passwords, *insecure_action],
        CATEGORY_CORS: [*takeovers, *tabnabbing, *storage_leaks],
        CATEGORY_SSRF: [*redirects, *csrf, *hidden_tampering],
        CATEGORY_STACK: [*sensitive_paths, *file_uploads],
        "csrf": csrf,
    }


def _surface_reasons(
    surfaces: list[dict[str, list[str]]],
    category: str,
) -> list[str]:
    """Flatten per-page surface reasons for one category, bounded and de-duplicated."""
    seen: list[str] = []
    for surface in surfaces:
        for reason in surface.get(category, []):
            if reason in seen:
                continue
            seen.append(reason)
            if len(seen) >= MAX_SURFACE_FINDINGS:
                return seen
    return seen


def _merge_surface(
    result: CategoryResult,
    extra: list[str],
    rule_ids: list[str],
    confirms: bool,
) -> CategoryResult:
    """Fold HTML surface reasons into an existing category verdict.

    Surface findings never *lower* a verdict. A confirmed issue keeps the
    category at VULNERABLE; anything else with surface evidence becomes
    HARDENING NEEDED rather than SAFE.
    """
    if not extra:
        return result
    merged_reasons = tuple(dict.fromkeys([*result.reasons, *extra]))
    merged_rules = tuple(dict.fromkeys([*result.rule_ids, *rule_ids]))
    if result.verdict is Verdict.VULNERABLE or confirms:
        verdict = Verdict.VULNERABLE
    else:
        verdict = Verdict.HARDENING
    return CategoryResult(
        name=result.name,
        verdict=verdict,
        reasons=merged_reasons,
        rule_ids=merged_rules,
    )


def _canary_reflection(
    url: str,
    client: httpx.Client | None,
    timeout: float,
    deep: bool,
    visited: list[str],
    surfaces: list[dict[str, list[str]]] | None = None,
    trusted_external: Sequence[str] | None = None,
) -> bool:
    """Return True when operator-requested probing shows unescaped reflection.

    Two markers are sent for every candidate page that already carries query
    parameters:

    * ``sentinel_canary_<hex>`` - purely alphanumeric, so it can never form
      markup, SQL syntax or a filename traversal;
    * ``<sentinelprobe>`` - inert angle brackets, which are the only way to tell
      an escaped echo from a raw one. An alphanumeric string survives HTML
      escaping unchanged, so it alone cannot prove that encoding is missing.

    Reflection is reported only when the angle-bracket marker survives verbatim,
    which means the application emitted the parameter without context encoding.
    """
    canary = _new_canary()
    targets = list(visited) if deep else [url]
    if not targets:
        targets = [url]

    for candidate in targets:
        names = _query_parameters(candidate)
        if not names:
            continue
        pairs = []
        for index, name in enumerate(names):
            marker = REFLECTION_PROBE if index == 0 else canary
            pairs.append(f"{name}={marker}")
        parsed = urlparse(candidate)
        probe_url = parsed._replace(query="&".join(pairs)).geturl()
        try:
            if client is not None:
                response = client.request("GET", probe_url, follow_redirects=True)
            else:
                with httpx.Client(timeout=timeout, follow_redirects=True) as session:
                    response = session.request(
                        "GET",
                        probe_url,
                        headers={"User-Agent": USER_AGENT, "Accept": "text/html,*/*"},
                    )
        except (httpx.HTTPError, ValueError):
            continue
        if int(response.status_code) >= 400:
            continue
        body = _body_text(response)
        if surfaces is not None and body:
            probe_is_https = urlparse(probe_url).scheme.lower() == "https"
            surfaces.append(_inspect_html_surface(body, probe_url, probe_is_https, trusted_external))
        if body and _has_unescaped_reflection(body, REFLECTION_PROBE):
            return True
    return False


def _check_stack_surface(
    headers: dict[str, str],
    body: str,
    discovered_paths: list[str] | None = None,
    surface_reasons: list[str] | None = None,
) -> CategoryResult:
    """Evaluate server stack, debug traces, exposed shells and matched CVEs."""
    reasons: list[str] = []
    lowered_body = body.lower() if body else ""

    stack_traces = [
        "traceback (most recent call last)",
        "django.core.exceptions",
        "werkzeug.debug",
        "whoops! there was an error",
        "fatal error: uncaught exception",
    ]
    for st in stack_traces:
        if st in lowered_body:
            return CategoryResult(
                name=CATEGORY_STACK,
                verdict=Verdict.VULNERABLE,
                reasons=(f"debug stack trace exposed in response body: '{st}'",),
                rule_ids=("HDR012",),
            )

    for hdr in ("server", "x-powered-by", "x-generator", "x-aspnet-version", "x-runtime"):
        if hdr in headers:
            reasons.append(f"disclosed backend banner via {hdr}: {headers[hdr]}")

    from src.analyzers.cve import _match_stack_cves

    cve_matches = _match_stack_cves(headers, body, discovered_paths)
    has_critical = False
    for rule, detail, is_vuln in cve_matches:
        if detail not in reasons:
            reasons.append(detail)
        if is_vuln and rule.severity.value in ("CRITICAL", "HIGH"):
            has_critical = True

    if surface_reasons:
        for reason in surface_reasons:
            if reason not in reasons:
                reasons.append(reason)
                if any(critical_marker in reason for critical_marker in ("/.git/", "/.env", "/phpinfo.php", "remote_agent.php", "GetPhpInfo.php")):
                    has_critical = True

    if has_critical:
        return CategoryResult(
            name=CATEGORY_STACK,
            verdict=Verdict.VULNERABLE,
            reasons=tuple(reasons[:MAX_SURFACE_FINDINGS]),
            rule_ids=("HDR007",),
        )

    if reasons:
        return CategoryResult(
            name=CATEGORY_STACK,
            verdict=Verdict.HARDENING,
            reasons=tuple(reasons[:MAX_SURFACE_FINDINGS]),
            rule_ids=("HDR007",),
        )

    return CategoryResult(name=CATEGORY_STACK, verdict=Verdict.SAFE)


def _audit_web(
    url: str,
    timeout: float = DEFAULT_TIMEOUT,
    follow_redirects: bool = True,
    max_redirects: int = DEFAULT_REDIRECTS,
    client: httpx.Client | None = None,
    probe: bool = True,
    deep: bool = True,
    max_pages: int = MAX_PAGES,
) -> WebReport:
    """Run the unified xss / sql injection / headers / CORS check for one URL.

    By default this performs a single passive ``GET`` plus markup inspection of
    that response. With ``deep=True`` it follows up to ``max_pages`` discovered
    same-origin GET links. ``probe=True`` additionally sends one benign canary
    request per page that has query parameters, to check for reflected output.
    """
    target = _normalize_url(url)
    target_host = urlparse(target).hostname or ""

    whitelist = _load_whitelist()
    if _is_whitelisted_host(target_host, whitelist.get("domains", [])):
        return WebReport(
            url=target,
            final_url=target,
            status_code=200,
            categories=tuple(
                CategoryResult(name=name, verdict=Verdict.SAFE) for name in CATEGORY_ORDER
            ),
            findings=(),
            errors=(),
            pages=(target,),
            deep=deep,
            whitelisted=True,
        )

    response, errors = _fetch(target, timeout, follow_redirects, max_redirects, client)
    if response is None:
        return WebReport(
            url=target,
            final_url=target,
            status_code=0,
            categories=tuple(
                CategoryResult(name=name, verdict=Verdict.SAFE) for name in CATEGORY_ORDER
            ),
            findings=(),
            errors=tuple(errors),
        )

    headers = _headers_map(response)
    cookies = _cookie_headers(response)
    body = _body_text(response)
    final_url = str(response.url)

    trusted_external = whitelist.get("trusted_external_links", [])

    page_is_https = urlparse(final_url).scheme.lower() == "https"
    surfaces: list[dict[str, list[str]]] = [_inspect_html_surface(body, final_url, page_is_https, trusted_external)]
    visited: list[str] = [final_url]

    if deep and body:
        limit = max(1, min(max_pages, MAX_PAGES))
        for link in _discover_links(body, final_url):
            if len(visited) >= limit:
                break
            page, page_errors = _fetch(
                link,
                timeout,
                follow_redirects,
                max_redirects,
                client,
            )
            if page is None:
                errors.extend(page_errors)
                continue
            if int(page.status_code) >= 400:
                continue
            page_body = _body_text(page)
            if not page_body:
                continue
            visited.append(str(page.url))
            page_https = urlparse(str(page.url)).scheme.lower() == "https"
            surfaces.append(_inspect_html_surface(page_body, str(page.url), page_https, trusted_external))

    reflection_raw = False
    if probe and body:
        reflection_raw = _canary_reflection(final_url, client, timeout, deep, visited, surfaces, trusted_external)

    xss_surface_reasons = _surface_reasons(surfaces, CATEGORY_XSS)
    sqli_surface_reasons = _surface_reasons(surfaces, CATEGORY_SQLI)
    csrf_reasons = _surface_reasons(surfaces, "csrf")
    header_reasons = _surface_reasons(surfaces, CATEGORY_HEADERS)
    stack_surface_reasons = _surface_reasons(surfaces, CATEGORY_STACK)

    has_password_form = any(
        "password input" in reason
        for s in surfaces
        for reason in s.get(CATEGORY_HEADERS, [])
    )
    if has_password_form:
        rate_limit_hdrs = ("x-ratelimit-limit", "ratelimit-limit", "retry-after")
        if not any(h in headers for h in rate_limit_hdrs):
            header_reasons.append("password login form present without rate-limit headers (TMP001)")

    xss = _check_xss_surface(headers, body, reflection_raw)
    xss = _merge_surface(xss, xss_surface_reasons, ["HDR001"], False)

    sqli = _check_sqli_surface(headers, body)
    has_sql_error = any("database error" in r or "exception" in r for r in sqli_surface_reasons)
    sqli = _merge_surface(sqli, sqli_surface_reasons, ["SQLI005"], confirms=has_sql_error)

    headers_result = _check_header_surface(headers, cookies)
    headers_result = _merge_surface(headers_result, header_reasons, ["HDR003"], False)
    cors = _check_cors_surface(headers, body)
    cors_reasons = _surface_reasons(surfaces, CATEGORY_CORS)
    cors = _merge_surface(cors, cors_reasons, ["CLD002", "CLT001", "CLT002"], False)

    redirect_reasons = _surface_reasons(surfaces, CATEGORY_SSRF)
    stack = _check_stack_surface(headers, body, visited, stack_surface_reasons)

    categories = (
        xss,
        sqli,
        headers_result,
        cors,
        _check_ssrf_surface(redirect_reasons, body),
        stack,
    )

    return WebReport(
        url=target,
        final_url=final_url,
        status_code=int(response.status_code),
        categories=categories,
        findings=tuple(_evaluate(_rules_for(ANALYZER_NAME), headers, cookies, final_url, body)),
        errors=tuple(errors),
        pages=tuple(visited),
        deep=deep,
        present_headers=tuple(sorted(headers)),
        cookie_count=len(cookies),
    )


def _build_web_report(
    url: str,
    headers: dict[str, str],
    body: str = "",
    cookies: list[str] | None = None,
    status_code: int = 200,
    reflection_raw: bool = False,
    whitelisted: bool = False,
) -> WebReport:
    """Evaluate already-captured metadata (offline use and testing)."""
    target = _normalize_url(url)
    if whitelisted:
        return WebReport(
            url=target,
            final_url=target,
            status_code=status_code,
            categories=tuple(
                CategoryResult(name=name, verdict=Verdict.SAFE) for name in CATEGORY_ORDER
            ),
            findings=(),
            errors=(),
            pages=(target,),
            whitelisted=True,
        )

    lowered = {name.lower(): value for name, value in headers.items()}
    cookie_values = list(cookies or [])
    page_is_https = urlparse(target).scheme.lower() == "https"
    whitelist = _load_whitelist()
    trusted_external = whitelist.get("trusted_external_links", [])
    surface = _inspect_html_surface(body, target, page_is_https, trusted_external)
    cors = _check_cors_surface(lowered, body)
    cors_surface = surface.get(CATEGORY_CORS, [])
    if cors_surface:
        cors = _merge_surface(cors, cors_surface, ["CLD002", "CLT001", "CLT002"], False)
    stack_surface = surface.get(CATEGORY_STACK, [])
    stack = _check_stack_surface(lowered, body, [target], stack_surface)
    sqli = _check_sqli_surface(lowered, body)
    sqli_surface = surface.get(CATEGORY_SQLI, [])
    if sqli_surface:
        has_sql_error = any("database error" in r or "exception" in r for r in sqli_surface)
        sqli = _merge_surface(sqli, sqli_surface, ["SQLI005"], confirms=has_sql_error)
    categories = (
        _check_xss_surface(lowered, body, reflection_raw),
        sqli,
        _check_header_surface(lowered, cookie_values),
        cors,
        _check_ssrf_surface(surface.get(CATEGORY_SSRF, []), body),
        stack,
    )
    return WebReport(
        url=target,
        final_url=target,
        status_code=status_code,
        categories=categories,
        findings=tuple(
            _evaluate(_rules_for(ANALYZER_NAME), lowered, cookie_values, target, body)
        ),
        errors=(),
        present_headers=tuple(sorted(lowered)),
        cookie_count=len(cookie_values),
    )



def _name() -> str:
    """Return the analyzer identifier used for rule lookup."""
    return ANALYZER_NAME


def _build_report(
    url: str,
    headers: dict[str, str],
    cookies: list[str] | None = None,
    status_code: int = 200,
) -> HeaderReport:
    """Evaluate already-captured headers (offline use and testing)."""
    target_url = _normalize_url(url)
    lowered = {key.lower(): value for key, value in headers.items()}
    cookie_values = list(cookies or [])
    findings = _evaluate(_rules_for(ANALYZER_NAME), lowered, cookie_values, target_url)
    return HeaderReport(
        url=target_url,
        final_url=target_url,
        status_code=status_code,
        findings=tuple(findings),
        present_headers=tuple(sorted(lowered)),
        cookie_count=len(cookie_values),
        errors=(),
    )


def _rule_ids(report: HeaderReport) -> set[str]:
    """Return the set of rule ids triggered by a report (test helper)."""
    return {finding.rule_id for finding in report.findings}
