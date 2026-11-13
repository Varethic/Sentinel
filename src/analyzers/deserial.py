"""Insecure deserialization static analyzer (DES001-DES002).

Detection is purely static: it inspects calls that reconstruct objects from a
byte stream (pickle/marshal/shelve) and YAML loaders that lack a safe loader.

No payload is ever constructed or deserialized here. The analyzer only reads
source text that the operator already owns.
"""

from __future__ import annotations

import ast

from src.core.engine import (
    DynamicKind,
    SourceFile,
    Visitor,
    _call_name,
    _dotted_name,
    _iter_subexpressions,
    _matches_module,
)
from src.core.loader import Rule, _rules_for

ANALYZER_NAME: str = "deserial"

MESSAGES: dict[str, str] = {
    "DES001": (
        "{sink}() reconstructs objects from a {format} byte stream; "
        "crafted bytes can execute arbitrary callables during unpickling"
    ),
    "DES002": (
        "yaml.{sink}() runs without SafeLoader/CSafeLoader; "
        "!!python tags in the document construct arbitrary objects"
    ),
}

BINARY_MODULES: frozenset[str] = frozenset(
    {"pickle", "_pickle", "cpickle", "marshal", "shelve", "dill"}
)

YAML_MODULES: frozenset[str] = frozenset({"yaml", "ruamel", "ruamel.yaml"})

SAFE_LOADERS: frozenset[str] = frozenset({"safeloader", "csafeloader", "baseloader"})

_FORMAT_LABELS: dict[str, str] = {
    "marshal": "marshal",
    "shelve": "shelve",
    "dill": "dill",
    "pickle": "pickle",
    "_pickle": "pickle",
    "cpickle": "pickle",
}


def _module_prefix(node: ast.Call) -> str:
    """Return the lowercase dotted module prefix of a call target."""
    dotted = _dotted_name(node.func).lower()
    if "." not in dotted:
        return ""
    return dotted.rsplit(".", 1)[0]


def _root_module(node: ast.Call) -> str:
    """Return the first dotted component of a call target, lowercased."""
    dotted = _dotted_name(node.func).lower()
    if not dotted:
        return ""
    return dotted.split(".", 1)[0]


def _matches_module_call(node: ast.Call, modules: frozenset[str]) -> str:
    """Return the matching module name for a call target, or ''.

    Thin wrapper over the shared engine helper so module matching behaves
    identically in every analyzer.
    """
    return _matches_module(_dotted_name(node.func), modules)


def _keyword_loader(node: ast.Call) -> str | None:
    """Return the dotted name of a loader= keyword argument, if given."""
    for keyword in node.keywords:
        if keyword.arg and keyword.arg.lower() == "loader":
            return _dotted_name(keyword.value).lower()
    return None


def _has_safe_loader(node: ast.Call) -> bool:
    """Return True when the call explicitly selects a safe YAML loader."""
    loader = _keyword_loader(node)
    if loader is None:
        return False
    final = loader.rsplit(".", 1)[-1]
    return final in SAFE_LOADERS


def _first_argument(node: ast.Call) -> ast.AST | None:
    """Return the first positional argument of a call, if any."""
    return node.args[0] if node.args else None


def _is_literal_argument(node: ast.Call) -> bool:
    """Return True when the payload is a literal the operator authored."""
    argument = _first_argument(node)
    return argument is not None and isinstance(argument, ast.Constant)


class DeserialVisitor(Visitor):
    """AST visitor implementing the deserialization rules."""

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802 - ast API name
        """Inspect every call that may reconstruct objects from data."""
        self._inspect(node)
        self.generic_visit(node)

    def _inspect(self, node: ast.Call) -> None:
        """Evaluate one call node against the configured rules."""
        name = _call_name(node)
        if not name:
            return

        des001 = self._rule("DES001")
        if des001 is not None and self._reports_binary(node, name, des001):
            return

        des002 = self._rule("DES002")
        if des002 is not None and self._reports_yaml(node, name, des002):
            return

    def _reports_binary(self, node: ast.Call, name: str, rule: Rule) -> bool:
        """pickle/marshal/shelve deserialization of non-literal data."""
        matched = _matches_module_call(node, BINARY_MODULES)
        if not matched:
            return False
        sinks = {sink.lower() for sink in rule.patterns._strings("sinks")}
        if name not in sinks:
            return False
        if _is_literal_argument(node):
            return False
        # shelve.open() takes a filename, not a byte stream, but it is still
        # a pickle-backed store and is reported with its own label.
        label = _FORMAT_LABELS.get(matched.split(".")[0], matched)
        self._add(
            rule.rule_id,
            node,
            MESSAGES["DES001"].format(sink=name, format=label),
        )
        return True

    def _reports_yaml(self, node: ast.Call, name: str, rule: Rule) -> bool:
        """yaml.load()/unsafe_load() without an explicit safe loader."""
        if not _matches_module_call(node, YAML_MODULES):
            return False
        sinks = {sink.lower() for sink in rule.patterns._strings("sinks")}
        if name not in sinks:
            return False
        # safe_load and safe_load_all are already safe by definition.
        if name.startswith("safe"):
            return False
        if _has_safe_loader(node):
            return False
        self._add(rule.rule_id, node, MESSAGES["DES002"].format(sink=name))
        return True


def _name() -> str:
    """Return the analyzer identifier used for rule lookup."""
    return ANALYZER_NAME


def _analyze(target: SourceFile) -> list:
    """Analyze one parsed source file for unsafe deserialization."""
    rules = _rules_for(ANALYZER_NAME)
    if not rules:
        return []
    return DeserialVisitor(target, rules)._run()


def _kind_of(node: ast.AST) -> DynamicKind:
    """Classify a payload expression for diagnostics callers."""
    for child in _iter_subexpressions(node):
        if isinstance(child, ast.JoinedStr):
            return DynamicKind.FSTRING
    return DynamicKind.NONE
