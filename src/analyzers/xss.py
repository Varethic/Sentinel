"""Cross-site scripting static analyzer (XSS001-XSS004).

The checks are static and conservative: they flag framework helpers that mark
content as trusted HTML, template sources assembled from dynamic values, and
auto-escaping explicitly switched off.
"""

from __future__ import annotations

import ast

from src.core.engine import (
    SourceFile,
    Visitor,
    _call_name,
    _contains_dynamic,
    _dynamic_kind,
    _iter_subexpressions,
    _string_value,
)
from src.core.loader import Rule, _rules_for

ANALYZER_NAME: str = "xss"

MESSAGES: dict[str, str] = {
    "XSS001": (
        "{sink}() marks a dynamic value as trusted HTML, disabling auto-escaping; "
        "escape() the value first"
    ),
    "XSS002": (
        "{sink}() receives a template whose source is built from dynamic input; "
        "render a static template file and pass data as context"
    ),
    "XSS003": (
        "template auto-escaping is disabled (autoescape=False) or HTML marked safe; "
        "keep auto-escaping enabled"
    ),
    "XSS004": (
        "{sink}() returns an HTML body assembled from dynamic values; "
        "render through a template with auto-escaping"
    ),
}

SAFE_WRAPPERS: frozenset[str] = frozenset(
    {"escape", "escape_html", "html_escape", "escapejs", "quote", "clean", "bleach"}
)

NON_HTML_MARKERS: frozenset[str] = frozenset(
    {"application/json", "text/plain", "application/octet-stream", "text/csv"}
)


def _call_keywords(node: ast.Call) -> dict[str, ast.AST]:
    """Return keyword arguments of a call keyed by name."""
    return {keyword.arg: keyword.value for keyword in node.keywords if keyword.arg}


def _is_safe_expression(node: ast.AST) -> bool:
    """Return True when an expression demonstrably neutralizes HTML content."""
    for child in _iter_subexpressions(node):
        if isinstance(child, ast.Call) and _call_name(child) in SAFE_WRAPPERS:
            return True
        if isinstance(child, ast.Attribute) and child.attr in {"escape", "escape_html"}:
            return True
    return False


def _has_dynamic_argument(node: ast.Call) -> bool:
    """Return True when a call receives a non-constant, unsanitized argument."""
    candidates: list[ast.AST] = []
    candidates.extend(node.args)
    candidates.extend(_call_keywords(node).values())
    for argument in candidates:
        if isinstance(argument, ast.Constant):
            continue
        if _is_safe_expression(argument):
            continue
        return True
    return False


def _disables_autoescape(node: ast.Call) -> bool:
    """Return True when a call explicitly sets autoescape to a false value."""
    for key, value in _call_keywords(node).items():
        if key == "autoescape" and isinstance(value, ast.Constant) and value.value is False:
            return True
    return False


def _select_autoescape_disabled(node: ast.Call) -> bool:
    """Return True for select_autoescape(enabled_extensions=/default=False)."""
    for key, value in _call_keywords(node).items():
        if key in {"default", "enabled"} and isinstance(value, ast.Constant):
            if value.value is False:
                return True
    return False


def _has_html_marker(node: ast.Call, markers: list[str]) -> bool:
    """Return True when the call builds an HTML document/body."""
    lowered = [marker.lower() for marker in markers]
    for child in _iter_subexpressions(node):
        text = _string_value(child)
        if text and any(marker in text.lower() for marker in lowered):
            return True
    return False


def _requests_non_html(node: ast.Call) -> bool:
    """Return True when the response explicitly declares a non-HTML type."""
    keywords = _call_keywords(node)
    for key in ("mimetype", "content_type", "media_type"):
        value = _string_value(keywords.get(key, ast.Constant(None)))
        if value and value.lower() in NON_HTML_MARKERS:
            return True
    return False


class XssVisitor(Visitor):
    """AST visitor implementing the XSS rules."""

    def visit_Call(self, node: ast.Call) -> None:
        """Inspect every call against the configured HTML sinks."""
        self._inspect(node)
        self.generic_visit(node)

    def _inspect(self, node: ast.Call) -> None:
        """Evaluate one call node against the XSS rules."""
        name = _call_name(node)
        if not name:
            return

        for rule in self._rules:
            sinks = {sink.lower() for sink in rule.patterns._strings("sinks")}
            if name not in sinks:
                continue
            handler = getattr(self, f"_check_{rule.rule_id.lower()}", None)
            if handler is None:
                continue
            if handler(rule, node, name):
                self._add(rule.rule_id, node, MESSAGES[rule.rule_id].format(sink=name))

    def _check_xss001(self, rule: Rule, node: ast.Call, name: str) -> bool:
        """Flag Markup()/mark_safe() applied to dynamic, unsanitized content."""
        if not rule.patterns._get("require_dynamic_argument", True):
            return False
        for argument in node.args:
            if isinstance(argument, ast.Constant):
                continue
            if _is_safe_expression(argument):
                continue
            if _dynamic_kind(argument) is not None:
                return True
            if _contains_dynamic(argument, rule.patterns._strings("dynamic_nodes")):
                return True
        return False

    def _check_xss002(self, rule: Rule, node: ast.Call, name: str) -> bool:
        """Flag template sources assembled from dynamic values."""
        if not node.args:
            return False
        source = node.args[0]
        if isinstance(source, ast.Constant):
            return False
        if _is_safe_expression(source):
            return False
        kinds = rule.patterns._strings("dynamic_nodes")
        return _contains_dynamic(source, kinds)

    def _check_xss003(self, rule: Rule, node: ast.Call, name: str) -> bool:
        """Flag explicit auto-escaping opt-out and unsafe raw HTML sinks."""
        if _disables_autoescape(node) or _select_autoescape_disabled(node):
            return True
        if name in {"safe"} and _has_dynamic_argument(node):
            return True
        return False

    def _check_xss004(self, rule: Rule, node: ast.Call, name: str) -> bool:
        """Flag HTML responses assembled from interpolated values."""
        if _requests_non_html(node):
            return False
        markers = rule.patterns._strings("html_markers")
        if not _has_html_marker(node, markers):
            return False
        if _is_safe_expression(node):
            return False
        return _has_dynamic_argument(node)


def _name() -> str:
    """Return the analyzer identifier used for rule lookup."""
    return ANALYZER_NAME


def _analyze(target: SourceFile) -> list:
    """Analyze one parsed source file for cross-site scripting patterns."""
    rules = _rules_for(ANALYZER_NAME)
    if not rules:
        return []
    return XssVisitor(target, rules)._run()


def _sink_names(rules: list[Rule] | None = None) -> set[str]:
    """Return the configured HTML sink names (useful for diagnostics/tests)."""
    catalog = rules if rules is not None else _rules_for(ANALYZER_NAME)
    names: set[str] = set()
    for rule in catalog:
        names.update(sink.lower() for sink in rule.patterns._strings("sinks"))
    return names


def _is_sanitized(node: ast.AST) -> bool:
    """Expose the sanitizer-detection helper for tests."""
    return _is_safe_expression(node)
