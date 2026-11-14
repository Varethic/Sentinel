"""API and GraphQL security static analyzer (API001-API002).

Detection is purely static: it inspects GraphQL schema construction for an
explicitly enabled introspection flag, and model instantiation for wholesale
unpacking of request data (mass assignment).

No query is executed and no request is issued here. The analyzer only reads
source text that the operator already owns.
"""

from __future__ import annotations

import ast

from src.core.engine import (
    SourceFile,
    Visitor,
    _call_arguments,
    _call_name,
    _dotted_name,
    _import_aliases,
    _iter_subexpressions,
    _matches_module,
    _resolve_dotted,
)
from src.core.loader import Rule, _rules_for

ANALYZER_NAME: str = "api"

MESSAGES: dict[str, str] = {
    "API001": (
        "{sink}() enables GraphQL introspection; the whole schema is published "
        "to unauthenticated callers"
    ),
    "API002": (
        "{model}(**{source}) unpacks request data into a model; "
        "a caller can set fields the endpoint never meant to expose"
    ),
}

GRAPHQL_MODULES: frozenset[str] = frozenset(
    {"graphene", "strawberry", "ariadne", "graphql", "graphql_core"}
)

REQUEST_SOURCES: frozenset[str] = frozenset(
    {"json", "form", "post", "data", "body", "json_body", "get_json", "query_params"}
)

MODEL_HINTS: frozenset[str] = frozenset(
    {"model", "schema", "base", "entity", "document", "table", "row"}
)


def _keyword_true(node: ast.Call, names: list[str]) -> bool:
    """Return True when one of the given keyword arguments is truthy True."""
    wanted = {name.lower() for name in names}
    for keyword in node.keywords:
        if keyword.arg and keyword.arg.lower() in wanted:
            value = keyword.value
            if isinstance(value, ast.Constant) and value.value is True:
                return True
    return False


def _reads_request_payload(node: ast.AST) -> bool:
    """Return True when an expression reads a whole request payload.

    Matches ``request.json()``, ``request.get_json()``, ``await request.json()``
    and attribute reads such as ``request.post`` or ``request.data``.
    """
    for child in _iter_subexpressions(node):
        if isinstance(child, ast.Attribute):
            if child.attr.lower() in REQUEST_SOURCES:
                return True
        if isinstance(child, ast.Call):
            name = _call_name(child)
            if name in REQUEST_SOURCES:
                return True
    return False


def _source_label(node: ast.AST) -> str:
    """Render a short label for the request accessor being unpacked."""
    for child in _iter_subexpressions(node):
        if isinstance(child, ast.Call):
            name = _call_name(child)
            if name in REQUEST_SOURCES:
                return f"request.{name}()"
        if isinstance(child, ast.Attribute) and child.attr.lower() in REQUEST_SOURCES:
            return f"request.{child.attr}"
    return "request data"


def _looks_like_model(node: ast.Call) -> bool:
    """Return True when a call target reads like a model or schema class."""
    dotted = _dotted_name(node.func)
    if not dotted:
        return False
    final = dotted.rsplit(".", 1)[-1]
    if not final or not final[0].isupper():
        return False
    return any(hint in final.lower() for hint in MODEL_HINTS)


class ApiVisitor(Visitor):
    """AST visitor implementing the API and GraphQL rules."""

    def __init__(self, target: SourceFile, rules: list[Rule]) -> None:
        """Store the file plus its import alias map."""
        super().__init__(target, rules)
        self._aliases = _import_aliases(target.tree)

    def visit_Call(self, node: ast.Call) -> None:
        """Inspect every call that may build a schema or a model."""
        self._inspect_introspection(node)
        self._inspect_mass_assignment(node)
        self.generic_visit(node)

    def _inspect_introspection(self, node: ast.Call) -> None:
        """Flag GraphQL schema construction with introspection enabled."""
        rule = self._rule("API001")
        if rule is None:
            return
        sinks = {sink.lower() for sink in rule.patterns._strings("sinks")}
        modules = frozenset(
            item.lower()
            for item in (rule.patterns._strings("sink_modules") or GRAPHQL_MODULES)
        )
        dotted = _resolve_dotted(_dotted_name(node.func), self._aliases)
        matched = _matches_module(dotted, modules)
        if not matched:
            return
        final = dotted.rsplit(".", 1)[-1]
        if final not in sinks and not _matches_module(
            dotted.rsplit(".", 1)[0] if "." in dotted else "", sinks
        ):
            return
        keywords = rule.patterns._strings("introspection_keywords") or [
            "introspection"
        ]
        if not _keyword_true(node, keywords):
            return
        self._add(
            rule.rule_id,
            node,
            MESSAGES["API001"].format(sink=_call_name(node)),
        )

    def _inspect_mass_assignment(self, node: ast.Call) -> None:
        """Flag Model(**request.json()) style wholesale unpacking."""
        rule = self._rule("API002")
        if rule is None:
            return
        for keyword in node.keywords:
            if keyword.arg is not None:
                continue
            if not _reads_request_payload(keyword.value):
                continue
            if not _looks_like_model(node):
                continue
            self._add(
                rule.rule_id,
                node,
                MESSAGES["API002"].format(
                    model=_dotted_name(node.func).rsplit(".", 1)[-1],
                    source=_source_label(keyword.value),
                ),
            )
            return


def _name() -> str:
    """Return the analyzer identifier used for rule lookup."""
    return ANALYZER_NAME


def _analyze(target: SourceFile) -> list:
    """Analyze one parsed source file for API and GraphQL issues."""
    rules = _rules_for(ANALYZER_NAME)
    if not rules:
        return []
    return ApiVisitor(target, rules)._run()
