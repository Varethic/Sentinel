"""Race condition and business logic flaw analyzer (LGC001-LGC002).

Detects concurrency race conditions on sensitive balances/stock operations without
row locking, and business logic flaws where financial/quantity inputs lack positive
bounds validation.
"""

from __future__ import annotations

import ast
from collections.abc import Sequence

from src.core.engine import Finding, SourceFile, Visitor, _call_name, _dotted_name
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

    def _scope_of(self, node: ast.AST) -> ast.AST:
        """Find the innermost enclosing function or the module root."""
        lineno = getattr(node, "lineno", 0)
        found: ast.AST = self._target.tree
        for candidate in ast.walk(self._target.tree):
            if not isinstance(candidate, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            start = getattr(candidate, "lineno", 0)
            end = getattr(candidate, "end_lineno", start)
            if start <= lineno <= end:
                found = candidate
        return found

    def _has_concurrency_lock(self, scope: ast.AST) -> bool:
        """Return True when scope uses DB row locking or thread/async locks."""
        if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for dec in scope.decorator_list:
                dname = _dotted_name(dec).lower()
                if any(tok in dname for tok in LOCK_TOKENS):
                    return True

        for child in ast.walk(scope):
            if isinstance(child, (ast.With, ast.AsyncWith)):
                for item in child.items:
                    wname = _dotted_name(item.context_expr).lower()
                    if any(tok in wname for tok in LOCK_TOKENS):
                        return True
            elif isinstance(child, ast.Call):
                cname = _dotted_name(child.func).lower()
                if any(tok in cname for tok in LOCK_TOKENS):
                    return True
        return False

    def _target_name(self, node: ast.AST) -> str:
        """Return the base variable or attribute name being mutated."""
        if isinstance(node, ast.Name):
            return node.id.lower()
        if isinstance(node, ast.Attribute):
            return node.attr.lower()
        return ""

    def _has_positive_bounds_check(self, scope: ast.AST, var_name: str) -> bool:
        """Return True if scope contains a comparison ensuring var_name is positive."""
        target = var_name.lower()
        for child in ast.walk(scope):
            if not isinstance(child, ast.If):
                continue
            for test in ast.walk(child.test):
                if isinstance(test, ast.Compare):
                    left_name = self._target_name(test.left)
                    comp_names = [self._target_name(comp) for comp in test.comparators]
                    if left_name == target or target in comp_names:
                        for op in test.ops:
                            if isinstance(op, (ast.Lt, ast.LtE, ast.Gt, ast.GtE)):
                                return True
        return False

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        """Inspect += and -= mutations on balance or inventory variables."""
        if isinstance(node.op, (ast.Sub, ast.Add)):
            tname = self._target_name(node.target)
            if any(k in tname for k in BALANCE_KEYWORDS):
                lineno = getattr(node, "lineno", 0)
                if lineno not in self._reported_lines:
                    scope = self._scope_of(node)
                    if not self._has_concurrency_lock(scope):
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
        # Check balance read-modify-write: obj.balance = obj.balance - amount
        if isinstance(node.value, ast.BinOp) and isinstance(node.value.op, (ast.Sub, ast.Add)):
            for target in node.targets:
                tname = self._target_name(target)
                if any(k in tname for k in BALANCE_KEYWORDS):
                    if lineno not in self._reported_lines:
                        scope = self._scope_of(node)
                        if not self._has_concurrency_lock(scope):
                            self._reported_lines.add(lineno)
                            self._add(
                                "LGC001",
                                node,
                                f"Race condition in balance/inventory update '{tname}' without concurrency lock or select_for_update",
                            )

        # Check input reading: amount = request.json.get("amount") without validation
        if isinstance(node.value, ast.Call):
            cname = _call_name(node.value)
            dname = _dotted_name(node.value.func).lower()
            if cname in {"get", "getlist", "getvalue"} or "request" in dname:
                for target in node.targets:
                    tname = self._target_name(target)
                    if any(f in tname for f in FINANCIAL_FIELDS):
                        scope = self._scope_of(node)
                        if not self._has_positive_bounds_check(scope, tname):
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
