"""SQL injection static analyzer (SQLI001-SQLI005).

Detection is purely static: it inspects the AST of database execution calls and
reports those whose query text is assembled from dynamic values instead of
being passed as a parameterized statement.
"""

from __future__ import annotations

import ast

from src.core.engine import (
    DynamicKind,
    SourceFile,
    Visitor,
    _call_name,
    _contains_dynamic,
    _dotted_name,
    _dynamic_kind,
    _iter_subexpressions,
    _mentions_sql,
    _string_value,
)
from src.core.loader import Rule, _rules_for

ANALYZER_NAME: str = "sqli"

MESSAGES: dict[str, str] = {
    "SQLI001": (
        "SQL query built with an f-string and passed to {sink}(); "
        "interpolated values become part of the query text"
    ),
    "SQLI002": (
        "SQL query built with '+' concatenation and passed to {sink}(); "
        "values are not bound as parameters"
    ),
    "SQLI003": (
        "SQL query built with '%' formatting and passed to {sink}(); "
        "values are not bound as parameters"
    ),
    "SQLI004": (
        "SQL query built with str.format()/string.Template and passed to {sink}(); "
        "substitution happens before parsing"
    ),
    "SQLI005": (
        "OR/M helper {sink}() receives interpolated SQL text; "
        "use bound parameters such as text(...).bindparams()"
    ),
}

FIRST_ARG_SINKS: frozenset[str] = frozenset(
    {"execute", "executemany", "executescript", "raw", "text"}
)

ORM_TEXT_SINKS: frozenset[str] = frozenset({"text", "raw"})


def _query_arguments(node: ast.Call) -> list[ast.AST]:
    """Return the positional arguments that may carry the SQL statement."""
    return list(node.args)


def _has_parameter_binding(node: ast.Call) -> bool:
    """Return True when the call binds parameters separately from the query."""
    if len(node.args) >= 2:
        return True
    for child in ast.walk(node):
        if isinstance(child, ast.Attribute) and child.attr == "bindparams":
            return True
    return False


def _looks_like_sql_argument(node: ast.AST, keywords: list[str]) -> bool:
    """Return True when an argument is (or contains) SQL-shaped text."""
    if _mentions_sql(node, keywords):
        return True
    return any(
        _mentions_sql(child, keywords)
        for child in _iter_subexpressions(node)
        if isinstance(child, ast.Constant)
    )


_BUILDING_KINDS: frozenset[DynamicKind] = frozenset(
    {
        DynamicKind.FSTRING,
        DynamicKind.CONCAT,
        DynamicKind.PERCENT,
        DynamicKind.FORMAT,
        DynamicKind.TEMPLATE,
    }
)


def _classify(node: ast.AST) -> DynamicKind:
    """Classify the dominant dynamic construction used by a query expression."""
    kind = _dynamic_kind(node)
    if kind in _BUILDING_KINDS:
        return kind
    for child in _iter_subexpressions(node):
        nested = _dynamic_kind(child)
        if nested in _BUILDING_KINDS:
            return nested
    return kind


class SqlVisitor(Visitor):
    """AST visitor implementing the SQL injection rules."""

    def __init__(self, target: SourceFile, rules: list[Rule]) -> None:
        super().__init__(target, rules)
        self._assignments: dict[str, ast.AST] = {}

    def visit_Assign(self, node: ast.Assign) -> None:
        for target in node.targets:
            if isinstance(target, ast.Name):
                self._assignments[target.id] = node.value
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if isinstance(node.target, ast.Name) and node.value is not None:
            self._assignments[node.target.id] = node.value
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        saved = dict(self._assignments)
        self.generic_visit(node)
        self._assignments = saved

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        saved = dict(self._assignments)
        self.generic_visit(node)
        self._assignments = saved

    def visit_Call(self, node: ast.Call) -> None:
        """Inspect every call whose name matches a configured SQL sink."""
        self._inspect(node)
        self.generic_visit(node)

    def _resolve_argument(self, argument: ast.AST) -> ast.AST:
        visited: set[str] = set()
        current = argument
        while (
            isinstance(current, ast.Name)
            and current.id in self._assignments
            and current.id not in visited
        ):
            visited.add(current.id)
            current = self._assignments[current.id]
        return current

    def _inspect(self, node: ast.Call) -> None:
        """Evaluate one call node against the configured SQL sink rules."""
        name = _call_name(node)
        if not name:
            return

        applicable = [
            rule
            for rule in self._rules
            if name in {sink.lower() for sink in rule.patterns._strings("sinks")}
        ]
        if not applicable:
            return

        keywords = applicable[0].patterns._strings("sql_keywords")
        applicable.sort(key=lambda rule: rule.rule_id != "SQLI005")
        for argument in _query_arguments(node):
            resolved = self._resolve_argument(argument)
            if not _looks_like_sql_argument(resolved, keywords):
                continue
            kind = _classify(resolved)
            for rule in applicable:
                rule_id = self._match(rule, name, kind, resolved, node)
                if rule_id is None:
                    continue
                self._add(rule_id, node, MESSAGES[rule_id].format(sink=name))
                break

    def _match(
        self,
        rule: Rule,
        name: str,
        kind: DynamicKind,
        argument: ast.AST,
        call: ast.Call,
    ) -> str | None:
        """Return the rule_id that applies to this call, if any."""
        dynamic_nodes = [item.lower() for item in rule.patterns._strings("dynamic_nodes")]
        bound = _has_parameter_binding(call)

        if rule.rule_id == "SQLI001":
            return rule.rule_id if kind is DynamicKind.FSTRING else None

        if rule.rule_id == "SQLI002":
            if kind is DynamicKind.CONCAT and not bound:
                return rule.rule_id
            return None

        if rule.rule_id == "SQLI003":
            return rule.rule_id if kind is DynamicKind.PERCENT else None

        if rule.rule_id == "SQLI004":
            if kind in (DynamicKind.FORMAT, DynamicKind.TEMPLATE):
                return rule.rule_id
            return None

        if rule.rule_id == "SQLI005":
            if name not in ORM_TEXT_SINKS:
                return None
            if _has_parameter_binding(call):
                return None
            if kind is DynamicKind.NONE and not _contains_dynamic(argument, dynamic_nodes):
                return None
            return rule.rule_id if kind is not DynamicKind.NONE else None

        return None


def _name() -> str:
    """Return the analyzer identifier used for rule lookup."""
    return ANALYZER_NAME


def _analyze(target: SourceFile) -> list:
    """Analyze one parsed source file for SQL injection patterns."""
    rules = _rules_for(ANALYZER_NAME)
    if not rules:
        return []
    return SqlVisitor(target, rules)._run()


def _sink_names(rules: list[Rule] | None = None) -> set[str]:
    """Return the configured SQL sink names (useful for diagnostics/tests)."""
    catalog = rules if rules is not None else _rules_for(ANALYZER_NAME)
    names: set[str] = set()
    for rule in catalog:
        names.update(sink.lower() for sink in rule.patterns._strings("sinks"))
    return names


def _dotted(node: ast.AST) -> str:
    """Expose the engine's dotted-name helper for callers and tests."""
    return _dotted_name(node)


def _as_text(node: ast.AST) -> str | None:
    """Expose the engine's string-literal helper for callers and tests."""
    return _string_value(node)
