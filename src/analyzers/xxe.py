"""XML External Entity static analyzer (XXE001-XXE002).

Detection is purely static: it inspects standard library XML parser calls and
lxml parser construction to find configurations that expand external entities.

No XML document is ever parsed here. The analyzer only reads source text that
the operator already owns.
"""

from __future__ import annotations

import ast

from src.core.engine import (
    SourceFile,
    Visitor,
    _call_name,
    _dotted_name,
    _import_aliases,
    _matches_module,
    _resolve_dotted,
)
from src.core.loader import Rule, _rules_for

ANALYZER_NAME: str = "xxe"

MESSAGES: dict[str, str] = {
    "XXE001": (
        "{sink}() from {module} parses XML with external entity expansion enabled; "
        "use defusedxml for untrusted documents"
    ),
    "XXE002": (
        "XMLParser configured with {setting}; this re-enables external entity "
        "resolution that lxml disables by default"
    ),
}

STANDARD_XML_MODULES: frozenset[str] = frozenset(
    {
        "xml",
        "xml.etree",
        "xml.etree.elementtree",
        "xml.dom",
        "xml.dom.minidom",
        "xml.sax",
        "minidom",
        "elementtree",
    }
)

LXML_MODULES: frozenset[str] = frozenset({"lxml", "lxml.etree", "etree"})

# Default unsafe keyword settings for lxml.etree.XMLParser.
UNSAFE_DEFAULTS: dict[str, bool] = {
    "resolve_entities": True,
    "no_network": False,
    "load_dtd": True,
    "dtd_validation": True,
}


def _keyword_bool(node: ast.Call, name: str) -> bool | None:
    """Return the boolean value of a keyword argument, or None if absent."""
    for keyword in node.keywords:
        if keyword.arg and keyword.arg.lower() == name.lower():
            value = keyword.value
            if isinstance(value, ast.Constant) and isinstance(value.value, bool):
                return value.value
    return None


def _is_defused(node: ast.Call) -> bool:
    """Return True when the parser call resolves to defusedxml."""
    return "defusedxml" in _dotted_name(node.func).lower()


def _first_argument(node: ast.Call) -> ast.AST | None:
    """Return the first positional argument of a call, if any."""
    return node.args[0] if node.args else None


def _is_literal(node: ast.AST | None) -> bool:
    """Return True when a node is a plain literal."""
    return isinstance(node, ast.Constant)


class XxeVisitor(Visitor):
    """AST visitor implementing the XXE rules."""

    def __init__(self, target: SourceFile, rules: list[Rule]) -> None:
        """Store the file plus its import alias map."""
        super().__init__(target, rules)
        self._aliases = _import_aliases(target.tree)

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802 - ast API name
        """Inspect every call that may construct or use an XML parser."""
        self._inspect(node)
        self.generic_visit(node)

    def _inspect(self, node: ast.Call) -> None:
        """Evaluate one call node against the configured XXE rules."""
        name = _call_name(node)
        if not name:
            return
        if _is_defused(node):
            return

        rule2 = self._rule("XXE002")
        if rule2 is not None and self._reports_unsafe_parser(node, name, rule2):
            return

        rule1 = self._rule("XXE001")
        if rule1 is not None and self._reports_stdlib(node, name, rule1):
            return

    def _reports_stdlib(self, node: ast.Call, name: str, rule: Rule) -> bool:
        """Standard library XML parsing of non-literal input."""
        dotted = _resolve_dotted(_dotted_name(node.func), self._aliases)
        module = _matches_module(dotted, STANDARD_XML_MODULES)
        if not module:
            return False
        sinks = {sink.lower() for sink in rule.patterns._strings("sinks")}
        if name not in sinks:
            return False
        argument = _first_argument(node)
        # A constant document authored in source is not external input.
        if argument is not None and _is_literal(argument):
            return False
        self._add(
            rule.rule_id,
            node,
            MESSAGES["XXE001"].format(sink=name, module=module),
        )
        return True

    def _reports_unsafe_parser(self, node: ast.Call, name: str, rule: Rule) -> bool:
        """lxml XMLParser built with entity resolution enabled."""
        dotted = _resolve_dotted(_dotted_name(node.func), self._aliases)
        if not _matches_module(dotted, LXML_MODULES) and name != "xmlparser":
            return False
        if name != "xmlparser":
            return False

        unsafe: list[str] = []
        for setting, dangerous in UNSAFE_DEFAULTS.items():
            value = _keyword_bool(node, setting)
            if value is None:
                continue
            if value is dangerous:
                unsafe.append(f"{setting}={dangerous}")
        if not unsafe:
            return False
        self._add(rule.rule_id, node, MESSAGES["XXE002"].format(setting=", ".join(unsafe)))
        return True


def _name() -> str:
    """Return the analyzer identifier used for rule lookup."""
    return ANALYZER_NAME


def _analyze(target: SourceFile) -> list:
    """Analyze one parsed source file for XXE patterns."""
    rules = _rules_for(ANALYZER_NAME)
    if not rules:
        return []
    return XxeVisitor(target, rules)._run()
