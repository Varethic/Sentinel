"""Path traversal static analyzer (PATH001-PATH003).

Detection is purely static: it inspects the AST of filesystem and file-serving
calls and reports those whose path argument is assembled from dynamic values
without a visible normalisation step.

The analyzer deliberately looks for *absent* mitigation rather than assuming the
worst: a path produced through ``.resolve()``, ``.relative_to()``,
``os.path.basename()``, ``werkzeug.utils.secure_filename()`` or similar is not
reported, so hardened code stays quiet.
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
    _string_value,
)
from src.core.loader import Rule, _rules_for

ANALYZER_NAME: str = "traversal"

MESSAGES: dict[str, str] = {
    "PATH001": (
        "filesystem path built from dynamic input and passed to {sink}(); "
        "no normalisation such as resolve()/relative_to() is visible"
    ),
    "PATH002": (
        "destructive filesystem call {sink}() receives a dynamic path; "
        "traversal can delete files outside the intended directory"
    ),
    "PATH003": (
        "framework file response {sink}() serves a dynamic path; "
        "traversal can disclose arbitrary files"
    ),
}

PATH_CONSTRUCTORS: frozenset[str] = frozenset(
    {"open", "path", "purepath", "posixpath", "windowspath", "open_file", "fileio"}
)

DESTRUCTIVE_SINKS: frozenset[str] = frozenset(
    {"remove", "unlink", "rmdir", "removedirs", "rmtree", "truncate"}
)

RESPONSE_SINKS: frozenset[str] = frozenset(
    {
        "send_file",
        "send_from_directory",
        "fileresponse",
        "static_file",
        "sendfile",
    }
)

DEFAULT_GUARDS: frozenset[str] = frozenset(
    {
        "resolve",
        "relative_to",
        "is_relative_to",
        "commonpath",
        "commonprefix",
        "abspath",
        "realpath",
        "normpath",
        "basename",
        "secure_filename",
        "safe_join",
        "quote",
        "quote_plus",
        "escape",
        "sanitize",
    }
)

DYNAMIC_KINDS: frozenset[str] = frozenset(
    {
        DynamicKind.FSTRING.value,
        DynamicKind.CONCAT.value,
        DynamicKind.PERCENT.value,
        DynamicKind.FORMAT.value,
        DynamicKind.TEMPLATE.value,
        DynamicKind.NAME.value,
    }
)


def _guard_names(rule: Rule) -> frozenset[str]:
    """Return the normalisation helpers configured for a rule."""
    configured = {name.lower() for name in rule.patterns._strings("guard_calls")}
    return frozenset(configured | DEFAULT_GUARDS)


def _parents_of(root: ast.AST, node: ast.AST) -> list[ast.AST]:
    """Return the ancestor chain of a node within a tree, nearest first."""
    chain: list[ast.AST] = []
    for candidate in ast.walk(root):
        for child in ast.iter_child_nodes(candidate):
            if child is node:
                chain.append(candidate)
    return chain


def _guarded_upward(root: ast.AST, node: ast.AST, guards: frozenset[str]) -> bool:
    """Return True when a guard is applied to the value this node produces.

    ``Path(x).resolve()`` guards the path even though the ``Path(...)`` call's
    own argument is a bare name, so the enclosing chain has to be inspected
    rather than the argument alone.
    """
    current: ast.AST = node
    for parent in _parents_of(root, node):
        if isinstance(parent, ast.Call) and parent.func is not current:
            if node in parent.args or any(kw.value is node for kw in parent.keywords):
                continue
        if isinstance(parent, ast.Call) and parent.func is current:
            if _call_name(parent) in guards:
                return True
        if isinstance(parent, ast.Attribute):
            if parent.attr.lower() in guards:
                return True
            current = parent
            continue
        if isinstance(parent, (ast.Assign, ast.Return, ast.AugAssign, ast.keyword)):
            break
        if isinstance(parent, ast.BinOp):
            current = parent
            continue
        if isinstance(parent, ast.Call):
            current = parent
            continue
        if isinstance(parent, (ast.Expr, ast.If, ast.For, ast.While)):
            break
        current = parent
    return False


def _is_guarded(node: ast.AST, guards: frozenset[str]) -> bool:
    """Return True when the expression applies a known path-normalisation call."""
    for child in _iter_subexpressions(node):
        if isinstance(child, ast.Call) and _call_name(child) in guards:
            return True
        if isinstance(child, ast.Attribute):
            if child.attr.lower() in guards:
                return True
    return False


def _is_literal(node: ast.AST) -> bool:
    """Return True for a plain constant path (e.g. open('config.json'))."""
    return isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes))


def _path_arguments(node: ast.Call) -> list[ast.AST]:
    """Return the positional arguments that may carry a filesystem path."""
    return list(node.args)


def _looks_dynamic(node: ast.AST) -> bool:
    """Return True when the expression is not a fixed literal."""
    if _is_literal(node):
        return False
    kind = _dynamic_kind(node)
    if kind.value in DYNAMIC_KINDS:
        return True
    return _contains_dynamic(node, DYNAMIC_KINDS)


def _classify(node: ast.AST) -> DynamicKind:
    """Classify the dominant dynamic construction used by a path expression."""
    kind = _dynamic_kind(node)
    if kind.value in DYNAMIC_KINDS:
        return kind
    for child in _iter_subexpressions(node):
        nested = _dynamic_kind(child)
        if nested.value in DYNAMIC_KINDS:
            return nested
    return kind


class TraversalVisitor(Visitor):
    """AST visitor implementing the path traversal rules."""

    def visit_Call(self, node: ast.Call) -> None:
        """Inspect every call that matches a configured filesystem sink."""
        self._inspect(node)
        self.generic_visit(node)

    def _inspect(self, node: ast.Call) -> None:
        """Evaluate one call node against the configured traversal rules."""
        name = _call_name(node)
        if not name:
            return

        for rule in self._rules:
            sinks = {sink.lower() for sink in rule.patterns._strings("sinks")}
            if name not in sinks:
                continue
            if self._reports(rule, node, name):
                self._add(rule.rule_id, node, MESSAGES[rule.rule_id].format(sink=name))
                return

    def _reports(self, rule: Rule, node: ast.Call, name: str) -> bool:
        """Return True when this call violates the given rule."""
        if rule.rule_id == "PATH001":
            if name not in PATH_CONSTRUCTORS:
                return False
        elif rule.rule_id == "PATH002":
            if name not in DESTRUCTIVE_SINKS:
                return False
        elif rule.rule_id == "PATH003":
            if name not in RESPONSE_SINKS:
                return False
        else:
            return False

        guards = _guard_names(rule)
        for argument in _path_arguments(node):
            if not _looks_dynamic(argument):
                continue
            if _is_guarded(argument, guards):
                continue
            if _guarded_upward(self._target.tree, node, guards):
                continue
            return True
        return False


def _name() -> str:
    """Return the analyzer identifier used for rule lookup."""
    return ANALYZER_NAME


def _analyze(target: SourceFile) -> list:
    """Analyze one parsed source file for path traversal patterns."""
    rules = _rules_for(ANALYZER_NAME)
    if not rules:
        return []
    return TraversalVisitor(target, rules)._run()


def _sink_names(rules: list[Rule] | None = None) -> set[str]:
    """Return the configured filesystem sink names (diagnostics helper)."""
    catalog = rules if rules is not None else _rules_for(ANALYZER_NAME)
    names: set[str] = set()
    for rule in catalog:
        names.update(sink.lower() for sink in rule.patterns._strings("sinks"))
    return names


def _is_traversal_safe(node: ast.AST) -> bool:
    """Expose guard detection for callers and tests."""
    return _is_guarded(node, DEFAULT_GUARDS)


def _as_text(node: ast.AST) -> str | None:
    """Expose the engine's string-literal helper for callers and tests."""
    return _string_value(node)


def _dotted(node: ast.AST) -> str:
    """Expose the engine's dotted-name helper for callers and tests."""
    return _dotted_name(node)
