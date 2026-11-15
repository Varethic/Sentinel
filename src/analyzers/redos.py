"""ReDoS and resource exhaustion static analyzer (DOS001-DOS002).

Detection is purely static: it inspects regular expression literals for nested
quantifiers that cause catastrophic backtracking, and outbound HTTP calls that
omit a timeout.

No pattern is ever evaluated and no request is issued here. The analyzer only
reads source text that the operator already owns.
"""

from __future__ import annotations

import ast
import re

from src.core.engine import (
    SourceFile,
    Visitor,
    _call_arguments,
    _call_name,
    _dotted_name,
    _matches_module,
    _string_value,
)
from src.core.loader import _rules_for

ANALYZER_NAME: str = "redos"

MESSAGES: dict[str, str] = {
    "DOS001": (
        "regular expression {pattern} passed to {sink}() has nested quantifiers; "
        "a failing match backtracks exponentially on attacker input"
    ),
    "DOS002": (
        "outbound request {sink}() has no timeout=; a slow peer blocks the worker indefinitely"
    ),
}

HTTP_MODULES: frozenset[str] = frozenset({"requests", "httpx", "urllib", "urllib3", "aiohttp"})

_NESTED_QUANTIFIER = re.compile(r"\([^()]*(?:[+*]|\{\d+,\d*\})[^()]*\)(?:[+*]|\{\d+,\d*\})")

_OVERLAPPING_ALTERNATION = re.compile(r"\([^()]*\|[^()]*\)(?:[+*]|\{\d+,\d*\})")

_LARGE_REPEAT = re.compile(r"\{\d{4,}(?:,\d*)?\}")


def _is_regex_module(node: ast.Call, modules: frozenset[str]) -> bool:
    """Return True when a call resolves to the ``re`` module or a ``regex`` module."""
    dotted = _dotted_name(node.func).lower()
    if not dotted:
        return False
    root = dotted.split(".", 1)[0]
    return root in {"re", "regex"} or root in modules


def _regex_literal(node: ast.Call) -> str | None:
    """Return the literal pattern text passed to a regex call, if static.

    ``re.compile(r"(a+)+")`` and ``re.search(r"(a+)+", data)`` both yield the
    pattern. A variable or f-string pattern is not analysed, because the value
    is not knowable statically.
    """
    for argument in _call_arguments(node):
        text = _string_value(argument)
        if text:
            return text
    return None


def _has_nested_quantifier(pattern: str) -> bool:
    """Return True when a pattern contains exponential backtracking shapes."""
    if not pattern:
        return False
    body = pattern
    body = re.sub(r"\\.", "", body)
    if _NESTED_QUANTIFIER.search(body):
        return True
    if _OVERLAPPING_ALTERNATION.search(body) and "|" in body:
        match = _OVERLAPPING_ALTERNATION.search(body)
        if match:
            inner = match.group(0)
            branches = inner[1 : inner.index(")")].split("|")
            heads = {branch[:1] for branch in branches if branch}
            if len(heads) < len([b for b in branches if b]):
                return True
    return bool(_LARGE_REPEAT.search(body))


def _has_timeout(node: ast.Call) -> bool:
    """Return True when the call passes an explicit timeout."""
    for keyword in node.keywords:
        if keyword.arg and keyword.arg.lower() in {"timeout", "timeouts"}:
            return True
    return False


def _is_http_sink(node: ast.Call, sinks: frozenset[str], modules: frozenset[str]) -> bool:
    """Return True when a call is an outbound HTTP helper."""
    name = _call_name(node)
    if name not in sinks:
        return False
    dotted = _dotted_name(node.func).lower()
    if name in {"urlopen", "urlretrieve"}:
        return True
    if _matches_module(dotted, modules):
        return True
    if isinstance(node.func, ast.Attribute):
        receiver = _dotted_name(node.func.value).lower()
        if any(token in receiver for token in modules):
            return True
    return False


class RedosVisitor(Visitor):
    """AST visitor implementing the ReDoS and timeout rules."""

    def visit_Call(self, node: ast.Call) -> None:
        """Inspect every call that may compile a regex or make a request."""
        self._inspect_regex(node)
        self._inspect_request(node)
        self.generic_visit(node)

    def _inspect_regex(self, node: ast.Call) -> None:
        """Flag regex calls whose literal pattern backtracks catastrophically."""
        rule = self._rule("DOS001")
        if rule is None:
            return
        sinks = {sink.lower() for sink in rule.patterns._strings("sinks")}
        if _call_name(node) not in sinks:
            return
        if not _is_regex_module(node, frozenset()):
            return
        pattern = _regex_literal(node)
        if pattern is None or not _has_nested_quantifier(pattern):
            return
        display = pattern if len(pattern) <= 60 else pattern[:57] + "..."
        self._add(
            rule.rule_id,
            node,
            MESSAGES["DOS001"].format(sink=_call_name(node), pattern=repr(display)),
        )

    def _inspect_request(self, node: ast.Call) -> None:
        """Flag outbound requests that omit a timeout."""
        rule = self._rule("DOS002")
        if rule is None:
            return
        sinks = {sink.lower() for sink in rule.patterns._strings("sinks")}
        modules = frozenset(
            item.lower() for item in (rule.patterns._strings("sink_modules") or HTTP_MODULES)
        )
        if not _is_http_sink(node, sinks, modules):
            return
        if _has_timeout(node):
            return
        self._add(
            rule.rule_id,
            node,
            MESSAGES["DOS002"].format(sink=_call_name(node)),
        )


def _name() -> str:
    """Return the analyzer identifier used for rule lookup."""
    return ANALYZER_NAME


def _analyze(target: SourceFile) -> list:
    """Analyze one parsed source file for ReDoS and timeout issues."""
    rules = _rules_for(ANALYZER_NAME)
    if not rules:
        return []
    return RedosVisitor(target, rules)._run()


def _is_catastrophic(pattern: str) -> bool:
    """Expose the nested-quantifier check for callers and diagnostics."""
    return _has_nested_quantifier(pattern)
