"""Server-Side Template Injection static analyzer (SSTI001).

Detection is purely static: it inspects template compilation calls and reports
those whose template *source* is a dynamic value rather than a static string.
Passing user data as a template *variable* is safe and is never reported.

No template is ever compiled or rendered here. The analyzer only reads source
text that the operator already owns.
"""

from __future__ import annotations

import ast

from src.core.engine import (
    DynamicKind,
    SourceFile,
    Visitor,
    _call_name,
    _dynamic_kind,
    _first_argument,
    _import_aliases,
    _iter_subexpressions,
    _resolve_import_sinks,
)
from src.core.loader import Rule, _rules_for

ANALYZER_NAME: str = "ssti"

MESSAGE: str = (
    "{sink}() compiles a template built with {kind}; "
    "template syntax is executable, so attacker input reaches template evaluation"
)

TEMPLATE_MODULES: frozenset[str] = frozenset(
    {
        "jinja2",
        "flask",
        "django",
        "django.template",
        "mako",
        "mako.template",
        "tornado",
        "bottle",
    }
)

# Callables whose first positional argument is the template *source*.
SOURCE_SINKS: frozenset[str] = frozenset(
    {"template", "render_template_string", "from_string", "templateresponse"}
)

# Callables that take a template *path/name*; safe even with a dynamic value.
PATH_SINKS: frozenset[str] = frozenset(
    {"render_template", "get_template", "select_template", "render"}
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


def _classify(node: ast.AST) -> DynamicKind:
    """Classify the dominant dynamic construction used by an expression."""
    kind = _dynamic_kind(node)
    if kind is not DynamicKind.NONE:
        return kind
    for child in _iter_subexpressions(node):
        nested = _dynamic_kind(child)
        if nested is not DynamicKind.NONE:
            return nested
    return DynamicKind.NONE


def _kind_label(kind: DynamicKind) -> str:
    """Return a human readable label for a dynamic construction kind."""
    return _KIND_LABELS.get(kind, "a value")


def _is_static_source(node: ast.AST | None) -> bool:
    """Return True when the template source is a fixed literal.

    A plain string literal is safe because the template author controls it. An
    f-string with no placeholders folds to a constant and is equally safe.
    """
    if node is None:
        return False
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, ast.JoinedStr):
        return all(isinstance(value, ast.Constant) for value in node.values)
    return False


class SstiVisitor(Visitor):
    """AST visitor implementing the SSTI rule."""

    def __init__(self, target: SourceFile, rules: list[Rule]) -> None:
        """Store the file plus the names bound to template classes."""
        super().__init__(target, rules)
        self._template_names = self._template_bindings()

    def _template_bindings(self) -> set[str]:
        """Return local names referring to a template class or helper."""
        return _resolve_import_sinks(self._target.tree, SOURCE_SINKS, TEMPLATE_MODULES)

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802 - ast API name
        """Inspect every call that may compile a template."""
        self._inspect(node)
        self.generic_visit(node)

    def _inspect(self, node: ast.Call) -> None:
        """Evaluate one call node against the SSTI rule."""
        rule = self._rule("SSTI001")
        if rule is None:
            return

        name = _call_name(node)
        if not name or name in PATH_SINKS:
            return
        if name not in SOURCE_SINKS and name not in self._template_names:
            return

        argument = _first_argument(node)
        if argument is None:
            return
        if _is_static_source(argument):
            return

        kind = _classify(argument)
        if kind is DynamicKind.NONE:
            return
        self._add(
            rule.rule_id,
            node,
            MESSAGE.format(sink=name, kind=_kind_label(kind)),
        )


def _name() -> str:
    """Return the analyzer identifier used for rule lookup."""
    return ANALYZER_NAME


def _analyze(target: SourceFile) -> list:
    """Analyze one parsed source file for template injection patterns."""
    rules = _rules_for(ANALYZER_NAME)
    if not rules:
        return []
    return SstiVisitor(target, rules)._run()
