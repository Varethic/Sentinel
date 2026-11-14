"""Command injection static analyzer (CMDI001-CMDI003).

Detection is purely static: it inspects the AST of shell-execution and
dynamic-code-execution calls and reports those whose command text is assembled
from dynamic values rather than being a fixed literal or an argument list.

No command is ever built or executed here. The analyzer only reads source text
that the operator already owns.
"""

from __future__ import annotations

import ast

from src.core.engine import (
    DynamicKind,
    SourceFile,
    Visitor,
    _call_name,
    _dotted_name,
    _dynamic_kind,
    _iter_subexpressions,
    _string_value,
)
from src.core.loader import Rule, _rules_for

ANALYZER_NAME: str = "cmdi"

MESSAGES: dict[str, str] = {
    "CMDI001": (
        "shell command built with {kind} and passed to {sink}(); "
        "interpolated values are parsed by the system shell"
    ),
    "CMDI002": (
        "subprocess call {sink}() uses shell=True with a dynamic command; "
        "shell metacharacters in the value are interpreted"
    ),
    "CMDI003": (
        "dynamic {sink}() call executes non-literal code; "
        "attacker-influenced input becomes arbitrary Python"
    ),
}

COMMAND_SINKS: frozenset[str] = frozenset(
    {
        "system",
        "popen",
        "popen2",
        "popen3",
        "popen4",
        "spawnl",
        "spawnv",
        "run",
        "call",
        "check_output",
        "check_call",
        "getoutput",
        "getstatusoutput",
    }
)

SHELL_SINKS: frozenset[str] = frozenset(
    {
        "run",
        "popen",
        "call",
        "check_output",
        "check_call",
        "getoutput",
        "getstatusoutput",
    }
)

DYNAMIC_SINKS: frozenset[str] = frozenset({"eval", "exec", "execfile"})

SAFE_EVAL_WRAPPERS: frozenset[str] = frozenset({"literal_eval"})

_KIND_LABELS: dict[DynamicKind, str] = {
    DynamicKind.FSTRING: "an f-string",
    DynamicKind.CONCAT: "'+' concatenation",
    DynamicKind.PERCENT: "'%' formatting",
    DynamicKind.FORMAT: "str.format()",
    DynamicKind.TEMPLATE: "string.Template",
    DynamicKind.NAME: "a variable",
    DynamicKind.NONE: "a value",
}


def _module_of(node: ast.AST) -> str:
    """Return the lowercase module prefix of a dotted call target, if any."""
    dotted = _dotted_name(node).lower()
    if "." not in dotted:
        return ""
    return dotted.rsplit(".", 1)[0]


def _kind_label(kind: DynamicKind) -> str:
    """Return a human readable label for a dynamic construction kind."""
    return _KIND_LABELS.get(kind, "a value")


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


def _is_literal(node: ast.AST) -> bool:
    """Return True when an expression is a plain literal (str/bytes/number)."""
    return isinstance(node, ast.Constant)


def _is_sequence_literal(node: ast.AST) -> bool:
    """Return True when the command is given as an argument list literal.

    ``subprocess.run(['ls', '-l'])`` is the recommended shape: no shell parsing
    happens, so it is never reported even when the list contains variables.
    """
    return isinstance(node, (ast.List, ast.Tuple))


def _keyword_true(node: ast.Call, names: list[str]) -> bool:
    """Return True when one of the given keyword arguments is truthy True."""
    wanted = {name.lower() for name in names}
    for keyword in node.keywords:
        if keyword.arg is None:
            continue
        if keyword.arg.lower() not in wanted:
            continue
        if isinstance(keyword.value, ast.Constant) and keyword.value.value is True:
            return True
    return False


def _keyword_value(node: ast.Call, name: str) -> ast.AST | None:
    """Return the value node for a keyword argument, if present."""
    for keyword in node.keywords:
        if keyword.arg and keyword.arg.lower() == name.lower():
            return keyword.value
    return None


def _first_argument(node: ast.Call) -> ast.AST | None:
    """Return the first positional argument of a call, if any."""
    return node.args[0] if node.args else None


class CmdiVisitor(Visitor):
    """AST visitor implementing the command injection rules."""

    def visit_Call(self, node: ast.Call) -> None:
        """Inspect every call that matches a configured command sink."""
        self._inspect(node)
        self.generic_visit(node)

    def _inspect(self, node: ast.Call) -> None:
        """Evaluate one call node against the configured command rules."""
        name = _call_name(node)
        if not name:
            return

        for rule in self._rules:
            sinks = {sink.lower() for sink in rule.patterns._strings("sinks")}
            if name not in sinks:
                continue
            if self._reports(rule, node, name):
                kind = _classify(_first_argument(node) or node)
                self._add(
                    rule.rule_id,
                    node,
                    MESSAGES[rule.rule_id].format(sink=name, kind=_kind_label(kind)),
                )
                return

    def _reports(self, rule: Rule, node: ast.Call, name: str) -> bool:
        """Return True when this call violates the given rule."""
        if rule.rule_id == "CMDI001":
            return self._reports_shell_string(node, name)
        if rule.rule_id == "CMDI002":
            return self._reports_subprocess_shell(node, name, rule)
        if rule.rule_id == "CMDI003":
            return self._reports_dynamic_eval(node, name)
        return False

    def _reports_shell_string(self, node: ast.Call, name: str) -> bool:
        """os.system()/os.popen() with a dynamically built command string."""
        if name not in COMMAND_SINKS:
            return False
        argument = _first_argument(node)
        if argument is None:
            return False
        if _is_literal(argument) or _is_sequence_literal(argument):
            return False
        return _classify(argument) is not DynamicKind.NONE

    def _reports_subprocess_shell(self, node: ast.Call, name: str, rule: Rule) -> bool:
        """subprocess.* with shell=True and a dynamic command."""
        if name not in SHELL_SINKS:
            return False
        shell_keywords = rule.patterns._strings("shell_keywords") or ["shell"]
        if not _keyword_true(node, shell_keywords):
            return False
        argument = _first_argument(node)
        if argument is None:
            return False
        if _is_literal(argument):
            return False
        return _classify(argument) is not DynamicKind.NONE

    def _reports_dynamic_eval(self, node: ast.Call, name: str) -> bool:
        """eval()/exec() applied to a non-literal expression."""
        if name in SAFE_EVAL_WRAPPERS:
            return False
        if name not in DYNAMIC_SINKS:
            return False
        argument = _first_argument(node)
        if argument is None:
            return False
        if _is_literal(argument):
            return False
        if isinstance(argument, ast.Call) and _call_name(argument) in SAFE_EVAL_WRAPPERS:
            return False
        if isinstance(argument, ast.JoinedStr) and all(
            isinstance(value, ast.Constant) for value in argument.values
        ):
            return False
        return True


def _name() -> str:
    """Return the analyzer identifier used for rule lookup."""
    return ANALYZER_NAME


def _analyze(target: SourceFile) -> list:
    """Analyze one parsed source file for command injection patterns."""
    rules = _rules_for(ANALYZER_NAME)
    if not rules:
        return []
    return CmdiVisitor(target, rules)._run()


def _sink_names(rules: list[Rule] | None = None) -> set[str]:
    """Return the configured command sink names (diagnostics helper)."""
    catalog = rules if rules is not None else _rules_for(ANALYZER_NAME)
    names: set[str] = set()
    for rule in catalog:
        names.update(sink.lower() for sink in rule.patterns._strings("sinks"))
    return names


def _as_text(node: ast.AST) -> str | None:
    """Expose the engine's string-literal helper for callers and tests."""
    return _string_value(node)
