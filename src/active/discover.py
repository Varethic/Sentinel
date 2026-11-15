"""HTML discovery helpers for the opt-in active verifier.

The module turns a page into a small set of injectable targets: GET forms,
query-string links, and login forms. It also exposes the full form inventory so
class-specific checks (XSS, SSTI, LFI, SSRF, XXE, JWT, ...) can decide which
fields to probe. Destructive actions (flag submission, environment reset,
uploads, coupon redemption) are skipped by both views.
"""

from __future__ import annotations

import contextlib
from dataclasses import dataclass
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urldefrag, urljoin, urlparse, urlunparse

MAX_TARGETS_PER_PAGE: int = 20
SKIP_PATH_PARTS: tuple[str, ...] = (
    "logout",
    "signout",
    "reset",
    "delete",
    "remove",
    "destroy",
    "shutdown",
    "upload",
)
SKIP_FORM_PATHS: frozenset[str] = frozenset(
    {
        "submit-flag",
        "reset-environment",
        "logout",
        "signout",
        "reset",
        "delete",
        "remove",
        "destroy",
        "shutdown",
        "upload",
        "redeem",
        "buy",
        "purchase",
    }
)
SKIP_EXTENSIONS: tuple[str, ...] = (
    ".css",
    ".js",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".ico",
    ".woff",
    ".woff2",
    ".ttf",
    ".map",
)
USER_HINTS: tuple[str, ...] = ("user", "login", "email", "account", "name")


@dataclass(frozen=True)
class DiscoveredTarget:
    """One parameter set on one endpoint that can be probed."""

    url: str
    method: str
    params: tuple[str, ...]
    login: bool = False
    user_field: str = "username"
    pass_field: str = "password"

    @property
    def label(self) -> str:
        """Return a short human-readable label for reports."""
        path = urlparse(self.url).path or "/"
        if self.login:
            return f"POST {path} (login)"
        return f"{self.method.upper()} {path}"


class _FormParser(HTMLParser):
    """Collect forms (with their inputs) and same-document links."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.forms: list[dict[str, object]] = []
        self.links: list[str] = []
        self._current: dict[str, object] | None = None
        self._inputs: list[tuple[str, str, str]]

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {key: (value or "") for key, value in attrs}
        if tag == "form":
            self._inputs = []
            self._current = {
                "action": values.get("action", ""),
                "method": values.get("method", "get").lower() or "get",
            }
        elif tag in {"input", "select", "textarea"} and self._current is not None:
            name = values.get("name", "").strip()
            if name:
                kind = values.get("type", "text").lower() or "text"
                self._inputs.append((name, kind, values.get("value", "")))
        elif tag == "a":
            href = values.get("href", "").strip()
            if href:
                self.links.append(href)

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._current is not None:
            self._current["inputs"] = tuple(self._inputs)
            self.forms.append(self._current)
            self._current = None
            self._inputs = []


def _same_origin(left: str, right: str) -> bool:
    """Return True when both URLs share scheme, host and port."""
    a = urlparse(left)
    b = urlparse(right)
    return (a.scheme, a.netloc.lower()) == (b.scheme, b.netloc.lower())


def _normalize_path(page_url: str, href: str) -> str:
    """Join href with page_url and strip fragment."""
    absolute = urljoin(page_url, href)
    parsed = urlparse(absolute)
    return parsed._replace(fragment="").geturl()


def _skippable(url: str) -> bool:
    """Return True for assets and destructive-looking endpoints."""
    parsed = urlparse(url)
    path = parsed.path.lower()
    if path.endswith(SKIP_EXTENSIONS):
        return True
    segments = [segment for segment in path.split("/") if segment]
    return any(part in segment for segment in segments for part in SKIP_PATH_PARTS)


def _form_skippable(url: str) -> bool:
    """Return True for destructive or asset endpoints."""
    parsed = urlparse(url)
    path = parsed.path.lower()
    if path.endswith(SKIP_EXTENSIONS):
        return True
    segments = [segment for segment in path.split("/") if segment]
    if any(part in segment for segment in segments for part in SKIP_PATH_PARTS):
        return True
    return any(needle in path for needle in SKIP_FORM_PATHS)


def _login_fields(inputs: tuple[tuple[str, str, str], ...]) -> tuple[str, str] | None:
    """Return (user, password) field names when the form looks like a login."""
    passwords = [name for name, kind, _value in inputs if kind == "password"]
    if not passwords:
        return None
    candidates = [
        name
        for name, kind, _value in inputs
        if kind != "password" and any(hint in name.lower() for hint in USER_HINTS)
    ]
    others = [
        name for name, kind, _value in inputs if kind != "password" and name not in candidates
    ]
    user = candidates[0] if candidates else (others[0] if others else "")
    if not user:
        return None
    return user, passwords[0]


def discover_page_targets(page_url: str, body: str) -> list[DiscoveredTarget]:
    """Return injectable targets found on one page.

    GET forms and query links become parameter probes. A POST form is included
    only when it has a password input, in which case it becomes a login-bypass
    target. Every other POST form is skipped to keep the run read-only.
    """
    parser = _FormParser()
    with contextlib.suppress(Exception):
        parser.feed(body)

    targets: list[DiscoveredTarget] = []
    seen: set[tuple[str, str, tuple[str, ...], bool]] = set()

    def add(target: DiscoveredTarget) -> None:
        key = (target.url, target.method, target.params, target.login)
        if key in seen or len(targets) >= MAX_TARGETS_PER_PAGE:
            return
        seen.add(key)
        targets.append(target)

    for form in parser.forms:
        action = urljoin(page_url, str(form["action"]) or page_url)
        if not _same_origin(action, page_url) or _skippable(action):
            continue
        method = str(form["method"]).upper()
        inputs = form["inputs"]
        if not isinstance(inputs, tuple):
            continue
        login_fields = _login_fields(inputs)
        if method == "POST" and login_fields is not None:
            user, password = login_fields
            add(
                DiscoveredTarget(
                    url=action,
                    method="POST",
                    params=(user, password),
                    login=True,
                    user_field=user,
                    pass_field=password,
                )
            )
            continue
        if method != "GET":
            continue
        names = tuple(dict.fromkeys(name for name, _kind, _value in inputs))
        if names:
            add(DiscoveredTarget(url=action, method="GET", params=names))

    for href in parser.links:
        absolute = urljoin(page_url, href)
        if not _same_origin(absolute, page_url) or _skippable(absolute):
            continue
        query = parse_qsl(urlparse(absolute).query, keep_blank_values=True)
        names = tuple(dict.fromkeys(name for name, _value in query if name))
        if not names:
            continue
        bare = urlunparse(urlparse(absolute)._replace(query="", fragment=""))
        add(DiscoveredTarget(url=bare, method="GET", params=names))

    return targets


@dataclass(frozen=True)
class DiscoveredForm:
    """One HTML form with all of its fields, for class-specific probing."""

    url: str
    method: str
    fields: tuple[tuple[str, str, str], ...]

    @property
    def label(self) -> str:
        path = urlparse(self.url).path or "/"
        return f"{self.method.upper()} {path}"

    @property
    def field_names(self) -> tuple[str, ...]:
        return tuple(name for name, _kind, _value in self.fields)

    def value(self, name: str, default: str = "") -> str:
        for field_name, _kind, field_value in self.fields:
            if field_name == name:
                return field_value or default
        return default


def discover_forms(page_url: str, body: str) -> list[DiscoveredForm]:
    """Return every same-origin form on the page, including POST actions."""
    parser = _FormParser()
    with contextlib.suppress(Exception):
        parser.feed(body)

    forms: list[DiscoveredForm] = []
    seen: set[tuple[str, str, tuple[tuple[str, str, str], ...]]] = set()
    for form in parser.forms:
        action = urldefrag(urljoin(page_url, str(form["action"]) or page_url)).url
        if not _same_origin(action, page_url) or _form_skippable(action):
            continue
        method = str(form["method"]).upper()
        inputs = form["inputs"]
        if not isinstance(inputs, tuple):
            continue
        key = (action, method, inputs)
        if key in seen:
            continue
        seen.add(key)
        forms.append(DiscoveredForm(url=action, method=method, fields=inputs))
    return forms


def crawl_links(page_url: str, body: str) -> list[str]:
    """Return same-origin, non-asset page links found in ``body``."""
    parser = _FormParser()
    with contextlib.suppress(Exception):
        parser.feed(body)
    found: list[str] = []
    seen: set[str] = set()
    for href in parser.links:
        absolute = _normalize_path(page_url, href)
        if not _same_origin(absolute, page_url) or _skippable(absolute):
            continue
        parsed = urlparse(absolute)
        bare = urlunparse(parsed._replace(fragment=""))
        if bare in seen:
            continue
        seen.add(bare)
        found.append(bare)
    return found
