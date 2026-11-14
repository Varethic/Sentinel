"""Race condition and business logic flaw analyzer (LGC001-LGC002).

Detects concurrency race conditions on sensitive balances/stock operations without
row locking, and business logic flaws where financial/quantity inputs lack positive
bounds validation.
"""

from __future__ import annotations

import ast
from collections.abc import Sequence

from src.core.engine import (
    Finding,
    SourceFile,
    Visitor,
    _call_name,
    _dotted_name,
    _enclosing_scope,
    _has_concurrency_lock,
    _has_positive_bounds_check,
)
from src.core.loader import Rule, _rules_for

ANALYZER_NAME: str = "logic"

BALANCE_KEYWORDS: frozenset[str] = frozenset(
    {"balance", "credit", "credits", "stock", "quantity", "inventory", "coupon"}
)
FINANCIAL_FIELDS: frozenset[str] = frozenset(
    {"amount", "price", "quantity", "qty", "count", "fee", "total"}
)
LOCK_TOKENS: frozenset[str] = frozenset(
    {
        "with_for_update",
        "select_for_update",
        "lock",
        "semaphore",
        "atomic",
        "transaction",
        "acquire",
        "mutex",
    }
)


class LogicVisitor(Visitor):
    """AST visitor detecting race conditions and unvalidated business logic."""

    def __init__(self, target: SourceFile, rules: Sequence[Rule]) -> None:
        super().__init__(target, rules)
        self._reported_lines: set[int] = set()

    def _target_name(self, node: ast.AST) -> str:
        """Return the base variable or attribute name being mutated."""
        if isinstance(node, ast.Name):
            return node.id.lower()
        if isinstance(node, ast.Attribute):
            return node.attr.lower()
        return ""

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        """Inspect += and -= mutations on balance or inventory variables."""
        if isinstance(node.op, (ast.Sub, ast.Add)):
            tname = self._target_name(node.target)
            if any(k in tname for k in BALANCE_KEYWORDS):
                lineno = getattr(node, "lineno", 0)
                if lineno not in self._reported_lines:
                    scope = _enclosing_scope(self._target.tree, node)
                    if not _has_concurrency_lock(scope, LOCK_TOKENS):
                        self._reported_lines.add(lineno)
                        self._add(
                            "LGC001",
                            node,
                            f"Race condition in balance/inventory mutation '{tname}' without concurrency lock or select_for_update",
                        )
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        """Inspect assignment mutations on balance/inventory and unvalidated inputs."""
        lineno = getattr(node, "lineno", 0)
        if isinstance(node.value, ast.BinOp) and isinstance(node.value.op, (ast.Sub, ast.Add)):
            for target in node.targets:
                tname = self._target_name(target)
                if any(k in tname for k in BALANCE_KEYWORDS):
                    if lineno not in self._reported_lines:
                        scope = _enclosing_scope(self._target.tree, node)
                        if not _has_concurrency_lock(scope, LOCK_TOKENS):
                            self._reported_lines.add(lineno)
                            self._add(
                                "LGC001",
                                node,
                                f"Race condition in balance/inventory update '{tname}' without concurrency lock or select_for_update",
                            )

        if isinstance(node.value, ast.Call):
            cname = _call_name(node.value)
            dname = _dotted_name(node.value.func).lower()
            if cname in {"get", "getlist", "getvalue"} or "request" in dname:
                for target in node.targets:
                    tname = self._target_name(target)
                    if any(f in tname for f in FINANCIAL_FIELDS):
                        scope = _enclosing_scope(self._target.tree, node)
                        if not _has_positive_bounds_check(scope, tname):
                            if lineno not in self._reported_lines:
                                self._reported_lines.add(lineno)
                                self._add(
                                    "LGC002",
                                    node,
                                    f"Financial or quantity input '{tname}' read from request without positive bounds validation (<= 0)",
                                )
        self.generic_visit(node)


def _analyze(target: SourceFile) -> list[Finding]:
    """Inspect one parsed source file for race condition and business logic flaws."""
    rules = _rules_for(ANALYZER_NAME)
    if not rules:
        return []
    visitor = LogicVisitor(target, rules)
    return visitor._run()


def _name() -> str:
    """Return the analyzer identifier matching logic.json."""
    return ANALYZER_NAME
