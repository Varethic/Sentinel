"""Server-Side Request Forgery static analyzer (SSRF001-SSRF002).

Detection is purely static: it inspects outbound HTTP client calls and reports
those whose destination URL is built from dynamic values without an obvious
allow-list guard, plus any call that targets a cloud metadata endpoint.

No request is ever issued here. The analyzer only reads source text that the
operator already owns.
"""

from __future__ import annotations

import ast

from src.core.engine import (
    DynamicKind,
    SourceFile,
    Visitor,
    _call_arguments,
    _call_name,
    _dotted_name,
    _is_guarded_scope,
    _iter_subexpressions,
    _mentions_guard,
    _string_value,
)
from src.core.loader import Rule, _rules_for

ANALYZER_NAME: str = "ssrf"

MESSAGES: dict[str, str] = {
    "SSRF001": (
        "outbound request {sink}() receives a URL built with {kind}; "
        "an attacker-influenced value redirects the server to an arbitrary host"
    ),
    "SSRF002": (
        "outbound request {sink}() targets the cloud metadata endpoint {host}; "
        "this exposes instance role credentials"
    ),
}

REQUEST_SINKS: frozenset[str] = frozenset(
    {"get", "post", "put", "patch", "delete", "head", "request", "urlopen", "urlretrieve"}
)

GUARD_TOKENS: frozenset[str] = frozenset(
    {
        "allowed",
        "allowlist",
        "whitelist",
        "is_safe",
        "issafe",
        "is_public",
        "ispublic",
        "validate_url",
        "validateurl",
        "sanitize_url",
        "sanitizeurl",
        "safe_url",
        "safeurl",
        "check_url",
        "checkurl",
    }
)

GUARD_CALLS: frozenset[str] = frozenset(
    {"is_allowed_host", "allowed_host", "is_allowed", "is_public_host"}
)

_KIND_LABELS: dict[DynamicKind, str] = {
    DynamicKind.FSTRING: "an f-string",
    DynamicKind.CONCAT: "'+' concatenation",
    DynamicKind.PERCENT: "'%' formatting",
    DynamicKind.FORMAT: "str.format()",
    DynamicKind.TEMPLATE: "string.Template",
    DynamicKind.NAME: "a variable",
    DynamicKind.NONE: "a value",
}


def _is_request_sink(node: ast.Call, sinks: frozenset[str], modules: frozenset[str]) -> bool:
    """Return True when a call is an outbound HTTP request helper.

    The receiver must resolve to an HTTP client module or session, so ordinary
    ``dict.get(...)`` / ``mapping.get(...)`` calls are never reported. Matches
    ``requests.get``, ``httpx.Client(...).get``, ``aiohttp.ClientSession().post``
    and bare ``urlopen`` once ``urllib.request`` has been imported.
    """
    name = _call_name(node)
    if name not in sinks:
        return False

    dotted = _dotted_name(node.func).lower()
    if not dotted:
        return False

    if dotted in {"urlopen", "urlretrieve"}:
        return True

    lowered_modules = {module.lower() for module in modules}
    tokens = {part for part in dotted.split(".") if part}
    if tokens & lowered_modules:
        return True

    if isinstance(node.func, ast.Attribute):
        receiver = node.func.value
        receiver_name = _dotted_name(receiver).lower()
        if any(token in receiver_name for token in lowered_modules):
            return True
        if isinstance(receiver, ast.Call):
            factory = _dotted_name(receiver.func).lower()
            if any(token in factory for token in lowered_modules):
                return True
    return False


def _classify(node: ast.AST) -> DynamicKind:
    """Classify the dominant dynamic construction used by an expression."""
    for child in _iter_subexpressions(node):
        if isinstance(child, ast.JoinedStr):
            return DynamicKind.FSTRING
        if isinstance(child, ast.BinOp):
            if isinstance(child.op, ast.Add):
                return DynamicKind.CONCAT
            if isinstance(child.op, ast.Mod):
                return DynamicKind.PERCENT
        if isinstance(child, ast.Call) and _call_name(child) == "format":
            return DynamicKind.FORMAT
    for child in _iter_subexpressions(node):
        if isinstance(child, (ast.Name, ast.Attribute, ast.Subscript)):
            return DynamicKind.NAME
    return DynamicKind.NONE


def _kind_label(kind: DynamicKind) -> str:
    """Return a human readable label for a dynamic construction kind."""
    return _KIND_LABELS.get(kind, "a value")


def _metadata_hosts(rules: list[Rule]) -> list[str]:
    """Return every configured cloud metadata host string."""
    hosts: list[str] = []
    for rule in rules:
        hosts.extend(rule.patterns._strings("metadata_hosts"))
    return hosts


def _literal_hosts(node: ast.AST) -> list[str]:
    """Return every string literal contained in an expression."""
    values: list[str] = []
    for child in _iter_subexpressions(node):
        text = _string_value(child)
        if text is not None:
            values.append(text)
    return values


class SsrfVisitor(Visitor):
    """AST visitor implementing the SSRF rules."""

    def __init__(self, target: SourceFile, rules: list[Rule]) -> None:
        """Store the file under analysis plus its applicable rules."""
        super().__init__(target, rules)

    def visit_Call(self, node: ast.Call) -> None:
        """Inspect every call that looks like an outbound HTTP request."""
        self._inspect(node)
        self.generic_visit(node)

    def _inspect(self, node: ast.Call) -> None:
        """Evaluate one call node against the configured SSRF rules."""
        sinks = frozenset(_sink_names())
        modules = frozenset(_module_names())
        if not _is_request_sink(node, sinks, modules):
            return

        for rule in self._rules:
            if rule.rule_id == "SSRF002" and self._reports_metadata(node, rule):
                return
            if rule.rule_id == "SSRF001" and self._reports_dynamic(node, rule):
                return

    def _reports_metadata(self, node: ast.Call, rule: Rule) -> bool:
        """Return True when the request targets a cloud metadata endpoint."""
        hosts = _metadata_hosts([rule])
        for argument in _call_arguments(node):
            for text in _literal_hosts(argument):
                lowered = text.lower()
                for host in hosts:
                    if host.lower() in lowered:
                        self._add(
                            rule.rule_id,
                            node,
                            MESSAGES["SSRF002"].format(
                                sink=_call_name(node), host=host
                            ),
                        )
                        return True
        return False

    def _reports_dynamic(self, node: ast.Call, rule: Rule) -> bool:
        """Return True when the destination URL is built from dynamic values."""
        argument = self._url_argument(node)
        if argument is None:
            return False
        if isinstance(argument, ast.Constant):
            return False
        if _mentions_guard(argument, GUARD_TOKENS):
            return False
        if _is_guarded_scope(self._target.tree, node, argument, GUARD_CALLS, GUARD_TOKENS):
            return False
        kind = _classify(argument)
        if kind is DynamicKind.NONE:
            return False
        self._add(
            rule.rule_id,
            node,
            MESSAGES["SSRF001"].format(sink=_call_name(node), kind=_kind_label(kind)),
        )
        return True

    def _url_argument(self, node: ast.Call) -> ast.AST | None:
        """Return the node carrying the destination URL for a request call."""
        if node.args:
            return node.args[0]
        for keyword in node.keywords:
            if keyword.arg and keyword.arg.lower() in {"url", "uri", "target"}:
                return keyword.value
        return None


def _sink_names(rules: list[Rule] | None = None) -> set[str]:
    """Return the configured outbound request sink names."""
    catalog = rules if rules is not None else _rules_for(ANALYZER_NAME)
    names: set[str] = set(REQUEST_SINKS)
    for rule in catalog:
        names.update(sink.lower() for sink in rule.patterns._strings("sinks"))
    return names


def _module_names(rules: list[Rule] | None = None) -> set[str]:
    """Return the configured HTTP client module names."""
    catalog = rules if rules is not None else _rules_for(ANALYZER_NAME)
    names: set[str] = {"requests", "httpx", "aiohttp", "urllib", "urllib3"}
    for rule in catalog:
        names.update(item.lower() for item in rule.patterns._strings("sink_modules"))
    return names


def _name() -> str:
    """Return the analyzer identifier used for rule lookup."""
    return ANALYZER_NAME


def _analyze(target: SourceFile) -> list:
    """Analyze one parsed source file for SSRF patterns."""
    rules = _rules_for(ANALYZER_NAME)
    if not rules:
        return []
    return SsrfVisitor(target, rules)._run()
