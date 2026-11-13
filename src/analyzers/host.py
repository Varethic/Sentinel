"""Host header injection and cache poisoning static analyzer (HST001-HST002).

Detection is purely static: it inspects Python source for unchecked usage of
the Host or X-Forwarded-Host request headers when building redirects, reset links,
or absolute URLs without allowlist validation.

No request is issued and no payload is sent. The analyzer only reads source
code that the operator already owns.
"""

from __future__ import annotations

import ast

from src.core.engine import (
    SourceFile,
    Visitor,
    _call_arguments,
    _call_name,
    _dotted_name,
    _iter_subexpressions,
    _string_value,
)
from src.core.loader import Rule, _rules_for

ANALYZER_NAME: str = "host"

MESSAGES: dict[str, str] = {
    "HST001": (
        "unvalidated Host header from {source} used in {sink}; "
        "enables host header injection and password reset poisoning"
    ),
    "HST002": (
        "response contains caching proxy header '{header}' without appropriate "
        "Vary header; vulnerable to cache poisoning"
    ),
}

_HOST_HEADERS: frozenset[str] = frozenset(
    {"host", "x-forwarded-host", "http_host", "http_x_forwarded_host"}
)

_HOST_ATTRS: frozenset[str] = frozenset(
    {"host", "get_host"}
)

_REDIRECT_SINKS: frozenset[str] = frozenset(
    {"redirect", "url_for", "urljoin", "send_reset_email", "send_mail"}
)

_CACHE_HEADERS: frozenset[str] = frozenset(
    {"x-cache", "cf-cache-status", "age", "via", "x-varnish", "x-drupal-cache"}
)


def _is_host_header_access(node: ast.AST) -> str | None:
    """Return the header name if the expression reads a Host request header."""
    if isinstance(node, ast.Subscript):
        key = _string_value(node.slice)
        if key and key.lower() in _HOST_HEADERS:
            return key
    if isinstance(node, ast.Call):
        name = _call_name(node).lower()
        if name in {"get", "get_host"}:
            if name == "get_host":
                return "get_host()"
            for arg in _call_arguments(node):
                val = _string_value(arg)
                if val and val.lower() in _HOST_HEADERS:
                    return val
    if isinstance(node, ast.Attribute):
        if node.attr.lower() in _HOST_ATTRS:
            return node.attr
    return None


def _contains_host_header(node: ast.AST) -> str | None:
    """Recursively check whether an expression reads a host header."""
    for sub in _iter_subexpressions(node):
        found = _is_host_header_access(sub)
        if found:
            return found
    return None


def _evaluate_cache_surface(headers: dict[str, str]) -> list[str]:
    """Inspect response headers for cache poisoning indicators (HST002)."""
    reasons: list[str] = []
    lowered = {k.lower(): v for k, v in headers.items()}
    found_cache_header: str | None = None
    for cache_hdr in _CACHE_HEADERS:
        if cache_hdr in lowered:
            found_cache_header = cache_hdr
            break

    if found_cache_header:
        vary = lowered.get("vary", "").lower()
        if "host" not in vary:
            reasons.append(
                f"caching header '{found_cache_header}' present without Vary: Host"
            )
    return reasons


class HostVisitor(Visitor):
    """AST visitor for Host header injection detection."""

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802 - ast API name
        """Inspect calls to redirect/link generators with Host expressions."""
        self._inspect_redirect_call(node)
        self.generic_visit(node)

    def visit_JoinedStr(self, node: ast.JoinedStr) -> None:  # noqa: N802 - ast API name
        """Inspect f-strings interpolating Host headers into URLs."""
        self._inspect_fstring(node)
        self.generic_visit(node)

    def _inspect_redirect_call(self, node: ast.Call) -> None:
        """Flag redirect() or urljoin() using Host header values directly."""
        rule = self._rule("HST001")
        if rule is None:
            return
        func_name = _call_name(node).lower()
        if func_name not in _REDIRECT_SINKS:
            return

        for arg in _call_arguments(node):
            source = _contains_host_header(arg)
            if source:
                self._add(
                    rule.rule_id,
                    node,
                    MESSAGES["HST001"].format(source=source, sink=f"{func_name}()"),
                )
                return

    def _inspect_fstring(self, node: ast.JoinedStr) -> None:
        """Flag f-string building URLs with Host headers."""
        rule = self._rule("HST001")
        if rule is None:
            return

        has_url_prefix = False
        host_source: str | None = None

        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                prefix = value.value.lower()
                if "http://" in prefix or "https://" in prefix or "//" in prefix:
                    has_url_prefix = True
            elif isinstance(value, ast.FormattedValue):
                found = _contains_host_header(value.value)
                if found:
                    host_source = found

        if has_url_prefix and host_source:
            self._add(
                rule.rule_id,
                node,
                MESSAGES["HST001"].format(
                    source=host_source, sink="URL f-string construction"
                ),
            )


def _name() -> str:
    """Return the analyzer identifier used for rule lookup."""
    return ANALYZER_NAME


def _analyze(target: SourceFile) -> list:
    """Analyze one parsed source file for Host header issues."""
    rules = _rules_for(ANALYZER_NAME)
    if not rules:
        return []
    return HostVisitor(target, rules)._run()
