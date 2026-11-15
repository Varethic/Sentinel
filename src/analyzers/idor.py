"""Insecure Direct Object Reference (IDOR) and broken access control static analyzer.

Detection is purely static: it inspects route/view handlers for unvalidated object
identifier lookups lacking user ownership checks (IDR001), and sensitive admin/internal
endpoints lacking authentication decorators (IDR002).

No database or endpoint is accessed. The analyzer only inspects Python source
text that the operator already owns.
"""

from __future__ import annotations

import ast

from src.core.engine import (
    SourceFile,
    Visitor,
    _call_arguments,
    _call_name,
    _has_auth_decorator,
    _is_route_decorator,
)
from src.core.loader import _rules_for

ANALYZER_NAME: str = "idor"

MESSAGES: dict[str, str] = {
    "IDR001": (
        "route parameter '{param}' is passed to ORM lookup {sink}() without an "
        "authenticated user or ownership guard in scope; vulnerable to IDOR"
    ),
    "IDR002": (
        "sensitive administrative route '{path}' on {handler}() lacks an "
        "authentication or authorization decorator (@login_required, Depends(...))"
    ),
}

_ID_PARAM_NAMES: frozenset[str] = frozenset(
    {
        "id",
        "user_id",
        "account_id",
        "order_id",
        "file_id",
        "doc_id",
        "item_id",
        "profile_id",
        "record_id",
        "invoice_id",
    }
)

_ORM_LOOKUP_METHODS: frozenset[str] = frozenset(
    {"get", "filter_by", "filter", "first_or_404", "find", "find_by_id"}
)

_AUTH_GUARDS: frozenset[str] = frozenset(
    {
        "current_user",
        "user",
        "session",
        "auth",
        "permission",
        "guard",
        "authorize",
        "is_admin",
        "role",
    }
)

_SENSITIVE_PATH_KEYWORDS: frozenset[str] = frozenset(
    {"/admin", "/internal", "/debug", "/metrics", "/_admin", "/manage"}
)

_AUTH_DECORATORS: frozenset[str] = frozenset(
    {
        "login_required",
        "admin_required",
        "requires_auth",
        "authenticated",
        "permission_required",
        "depends",
        "jwt_required",
        "auth_required",
        "protect",
        "check_permissions",
    }
)


def _function_references_auth(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """Return True if the function body references common auth objects or sessions."""
    for sub in ast.walk(node):
        if isinstance(sub, ast.Name) and sub.id.lower() in _AUTH_GUARDS:
            return True
        if isinstance(sub, ast.Attribute) and sub.attr.lower() in _AUTH_GUARDS:
            return True
    return False


class IdorVisitor(Visitor):
    """AST visitor detecting IDOR and unauthenticated admin endpoints."""

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Inspect synchronous handler definitions."""
        self._inspect_function(node)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        """Inspect asynchronous handler definitions."""
        self._inspect_function(node)
        self.generic_visit(node)

    def _inspect_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        """Evaluate a function for IDOR and sensitive unauthenticated routes."""
        is_route = False
        route_path = ""
        for dec in node.decorator_list:
            matched, path, _ = _is_route_decorator(dec)
            if matched:
                is_route = True
                if path:
                    route_path = path

        if not is_route and not any(arg.arg.lower() in _ID_PARAM_NAMES for arg in node.args.args):
            return

        self._check_idor_queries(node, is_route)
        if is_route and route_path:
            self._check_admin_auth(node, route_path)

    def _check_admin_auth(self, node: ast.FunctionDef | ast.AsyncFunctionDef, path: str) -> None:
        """Flag sensitive admin or internal routes lacking authentication (IDR002)."""
        rule = self._rule("IDR002")
        if rule is None:
            return

        is_sensitive = any(kw in path.lower() for kw in _SENSITIVE_PATH_KEYWORDS)
        if not is_sensitive:
            return

        if _has_auth_decorator(node.decorator_list):
            return

        self._add(
            rule.rule_id,
            node,
            MESSAGES["IDR002"].format(path=path, handler=node.name),
        )

    def _check_idor_queries(
        self, node: ast.FunctionDef | ast.AsyncFunctionDef, is_route: bool
    ) -> None:
        """Flag ORM lookups using route id params without auth guard (IDR001)."""
        rule = self._rule("IDR001")
        if rule is None:
            return

        param_names = {
            arg.arg.lower() for arg in node.args.args if arg.arg.lower() in _ID_PARAM_NAMES
        }
        if not param_names:
            return

        if _function_references_auth(node):
            return

        for sub in ast.walk(node):
            if not isinstance(sub, ast.Call):
                continue
            method_name = _call_name(sub).lower()
            if method_name not in _ORM_LOOKUP_METHODS:
                continue

            for arg in _call_arguments(sub):
                if isinstance(arg, ast.Name) and arg.id.lower() in param_names:
                    self._add(
                        rule.rule_id,
                        sub,
                        MESSAGES["IDR001"].format(param=arg.id, sink=f"{method_name}()"),
                    )
                    return
                if isinstance(arg, ast.keyword) and (
                    isinstance(arg.value, ast.Name) and arg.value.id.lower() in param_names
                ):
                    self._add(
                        rule.rule_id,
                        sub,
                        MESSAGES["IDR001"].format(param=arg.value.id, sink=f"{method_name}()"),
                    )
                    return


def _name() -> str:
    """Return the analyzer identifier used for rule lookup."""
    return ANALYZER_NAME


def _analyze(target: SourceFile) -> list:
    """Analyze one parsed source file for IDOR and access control issues."""
    rules = _rules_for(ANALYZER_NAME)
    if not rules:
        return []
    return IdorVisitor(target, rules)._run()
