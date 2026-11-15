"""Deprecated and insecure module usage static analyzer (DEP001-DEP002).

Detection is purely static: it inspects import statements for modules that are
removed from the standard library or documented as unsafe, and attribute
references that pin a withdrawn TLS protocol version.

Nothing is imported or executed. The analyzer only reads source text that the
operator already owns.
"""

from __future__ import annotations

import ast

from src.core.engine import (
    SourceFile,
    Visitor,
    _dotted_name,
    _import_aliases,
    _resolve_dotted,
)
from src.core.loader import Rule, _rules_for

ANALYZER_NAME: str = "deps"

MESSAGES: dict[str, str] = {
    "DEP001": (
        "module {module} is deprecated or unsafe; it is removed from the "
        "standard library or transmits data in clear text"
    ),
    "DEP002": (
        "ssl.{attribute} selects a withdrawn TLS or SSL protocol; "
        "negotiate TLS 1.2+ with ssl.create_default_context()"
    ),
}

DEFAULT_DENYLIST: tuple[str, ...] = (
    "telnetlib",
    "ftplib",
    "imp",
    "cgi",
    "pickletools",
    "asynchat",
    "asyncore",
    "smtpd",
    "distutils",
)

DEFAULT_PROTOCOLS: tuple[str, ...] = (
    "PROTOCOL_TLSv1",
    "PROTOCOL_TLSv1_1",
    "PROTOCOL_SSLv3",
    "PROTOCOL_SSLv23",
)

_SEVERITY_RANK: dict[str, int] = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


def _module_matches(name: str, denylist: set[str]) -> str:
    """Return the denied module that a dotted import name belongs to."""
    lowered = (name or "").lower()
    if not lowered:
        return ""
    for entry in denylist:
        if lowered == entry or lowered.startswith(entry + "."):
            return entry
    return ""


class DepsVisitor(Visitor):
    """AST visitor implementing the deprecated-module and TLS rules."""

    def __init__(self, target: SourceFile, rules: list[Rule]) -> None:
        """Store the file plus the set of already reported modules."""
        super().__init__(target, rules)
        self._aliases = _import_aliases(target.tree)
        self._reported: set[str] = set()

    def visit_Import(self, node: ast.Import) -> None:
        """Flag plain imports of denied modules."""
        self._inspect_import(node, [alias.name for alias in node.names])
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Flag from-imports of denied modules."""
        if node.module:
            self._inspect_import(node, [node.module])
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        """Flag attribute access that pins a withdrawn TLS protocol."""
        self._inspect_protocol(node)
        self.generic_visit(node)

    def _inspect_import(self, node: ast.AST, names: list[str]) -> None:
        """Report a denied module once per file."""
        rule = self._rule("DEP001")
        if rule is None:
            return
        denylist = {
            entry.lower() for entry in (rule.patterns._strings("modules") or DEFAULT_DENYLIST)
        }
        for name in names:
            matched = _module_matches(name, denylist)
            if not matched or matched in self._reported:
                continue
            self._reported.add(matched)
            self._add(
                rule.rule_id,
                node,
                MESSAGES["DEP001"].format(module=matched),
            )

    def _inspect_protocol(self, node: ast.Attribute) -> None:
        """Report a reference to a withdrawn TLS protocol constant."""
        rule = self._rule("DEP002")
        if rule is None:
            return
        protocols = {entry for entry in (rule.patterns._strings("attributes") or DEFAULT_PROTOCOLS)}
        if node.attr not in protocols:
            return
        owner = _dotted_name(node.value).lower()
        resolved = _resolve_dotted(owner, self._aliases)
        if owner != "ssl" and resolved != "ssl" and not resolved.startswith("ssl."):
            return
        key = f"protocol:{node.attr}"
        if key in self._reported:
            return
        self._reported.add(key)
        self._add(
            rule.rule_id,
            node,
            MESSAGES["DEP002"].format(attribute=node.attr),
        )


def _name() -> str:
    """Return the analyzer identifier used for rule lookup."""
    return ANALYZER_NAME


def _analyze(target: SourceFile) -> list:
    """Analyze one parsed source file for deprecated and insecure usage."""
    rules = _rules_for(ANALYZER_NAME)
    if not rules:
        return []
    return DepsVisitor(target, rules)._run()
