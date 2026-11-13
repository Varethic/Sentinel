"""Rate-limiting, brute-force protection, and request/parameter tampering analyzer (TMP001-TMP005).

Detection is purely static and non-destructive: it inspects route handlers for missing
rate limits on auth endpoints (TMP001), trusting untrusted client parameters for
sensitive privilege/pricing state (TMP002), and HTTP verb override/tampering (TMP003).

No brute-force or mutating requests are ever issued. The analyzer only evaluates
source text and passive response markup.
"""

from __future__ import annotations

import ast
from collections.abc import Sequence

from src.core.engine import (
    SourceFile,
    Visitor,
    _call_arguments,
    _call_name,
    _dotted_name,
    _string_value,
)
from src.core.loader import Rule, _rules_for

ANALYZER_NAME: str = "tamper"

MESSAGES: dict[str, str] = {
    "TMP001": (
        "authentication route '{path}' on {handler}() lacks rate-limiting or "
        "throttling protection; vulnerable to brute-force and credential stuffing"
    ),
    "TMP002": (
        "sensitive parameter '{param}' is read directly from request data in {sink}() "
        "without server-side validation; vulnerable to parameter tampering"
    ),
    "TMP003": (
        "handler reads method override header '{header}' or accepts both GET and mutating "
        "verbs on state-changing route '{path}'; vulnerable to HTTP verb tampering"
    ),
    "TMP004": (
        "handler reads query parameter '{param}' without verifying multiplicity; "
        "vulnerable to HTTP parameter pollution"
    ),
    "TMP005": (
        "hidden form field '{field}' reflects client state without cryptographic signature"
    ),
}

_AUTH_ROUTE_KEYWORDS: frozenset[str] = frozenset(
    {"/login", "/signin", "/token", "/otp", "/reset-password", "/auth", "/password"}
)

_RATE_LIMIT_DECORATORS: frozenset[str] = frozenset(
    {"limiter", "throttle", "ratelimit", "slowapi", "rate_limit", "limit"}
)

_SENSITIVE_PARAM_NAMES: frozenset[str] = frozenset(
    {"price", "amount", "discount", "role", "is_admin", "admin", "credits", "balance"}
)

_OVERRIDE_HEADERS: frozenset[str] = frozenset(
    {"x-http-method-override", "x-method-override", "x-http-method"}
)

_RATE_LIMIT_HEADERS: tuple[str, ...] = (
    "x-ratelimit-limit",
    "ratelimit-limit",
    "retry-after",
    "x-rate-limit-limit",
)


def _is_route_decorator(dec: ast.AST) -> tuple[bool, str, list[str]]:
    """Check if decorator registers a route; return (is_route, path, methods)."""
    call_node: ast.Call | None = dec if isinstance(dec, ast.Call) else None
    if call_node is None:
        return False, "", []

    dotted = _dotted_name(call_node.func).lower()
    route_indicators = {"route", "get", "post", "put", "delete", "patch"}
    if not any(token in dotted for token in route_indicators):
        return False, "", []

    path = ""
    methods: list[str] = []
    for arg in _call_arguments(call_node):
        val = _string_value(arg)
        if val and val.startswith("/"):
            path = val

    for kw in call_node.keywords:
        if kw.arg == "methods" and isinstance(kw.value, (ast.List, ast.Tuple, ast.Set)):
            for elt in kw.value.elts:
                s = _string_value(elt)
                if s:
                    methods.append(s.upper())

    return True, path, methods


def _has_rate_limit(decorators: list[ast.AST]) -> bool:
    """Return True if any decorator looks like a rate limiter."""
    for dec in decorators:
        node = dec.func if isinstance(dec, ast.Call) else dec
        dotted = _dotted_name(node).lower()
        if any(kw in dotted for kw in _RATE_LIMIT_DECORATORS):
            return True
    return False


def _evaluate_tamper_surface(
    forms: list[dict[str, object]],
    headers: dict[str, str],
    password_inputs: list[str],
) -> list[str]:
    """Inspect markup forms and response headers for tampering and brute-force risks."""
    reasons: list[str] = []
    lowered_headers = {k.lower(): v for k, v in headers.items()}

    # Check for missing rate limits when login/password inputs exist (TMP001)
    if password_inputs:
        has_rate_header = any(hdr in lowered_headers for hdr in _RATE_LIMIT_HEADERS)
        if not has_rate_header:
            reasons.append(
                "login/password form served without rate-limit headers (X-RateLimit-Limit, Retry-After)"
            )

    # Check for sensitive parameters exposed in hidden fields (TMP002 / TMP005)
    for form in forms:
        fields = form.get("fields")
        if not isinstance(fields, list):
            continue
        for field in fields:
            if not isinstance(field, dict):
                continue
            ftype = str(field.get("type") or "").lower()
            fname = str(field.get("name") or "").lower()
            if ftype == "hidden" and any(param in fname for param in _SENSITIVE_PARAM_NAMES):
                reasons.append(
                    f"sensitive parameter '{fname}' exposed in hidden form field without tamper protection"
                )

    return reasons


class TamperVisitor(Visitor):
    """AST visitor for rate-limiting, parameter tampering, and verb override."""

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # noqa: N802
        """Inspect synchronous route handlers."""
        self._inspect_handler(node)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:  # noqa: N802
        """Inspect asynchronous route handlers."""
        self._inspect_handler(node)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
        """Inspect calls reading request data or headers."""
        self._inspect_request_call(node)
        self.generic_visit(node)

    def _inspect_handler(
        self, node: ast.FunctionDef | ast.AsyncFunctionDef
    ) -> None:
        """Evaluate route handlers for missing rate limits and verb tampering."""
        is_route = False
        route_path = ""
        methods: list[str] = []

        for dec in node.decorator_list:
            matched, path, m = _is_route_decorator(dec)
            if matched:
                is_route = True
                if path:
                    route_path = path
                if m:
                    methods = m

        if not is_route:
            return

        # Check TMP001: Missing rate limits on auth routes
        self._check_auth_rate_limit(node, route_path)

        # Check TMP003: Verb tampering (combining GET and mutating verbs on same handler)
        self._check_verb_tampering(node, route_path, methods)

    def _check_auth_rate_limit(
        self, node: ast.FunctionDef | ast.AsyncFunctionDef, path: str
    ) -> None:
        """Flag authentication routes lacking rate-limiting decorators (TMP001)."""
        rule = self._rule("TMP001")
        if rule is None:
            return

        is_auth = any(kw in path.lower() for kw in _AUTH_ROUTE_KEYWORDS)
        if not is_auth:
            return

        if _has_rate_limit(node.decorator_list):
            return

        self._add(
            rule.rule_id,
            node,
            MESSAGES["TMP001"].format(path=path, handler=node.name),
        )

    def _check_verb_tampering(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        path: str,
        methods: list[str],
    ) -> None:
        """Flag routes binding both safe GET and mutating verbs to the same handler (TMP003)."""
        rule = self._rule("TMP003")
        if rule is None:
            return

        has_get = "GET" in methods
        has_mutating = any(m in methods for m in ("POST", "DELETE", "PUT", "PATCH"))

        if has_get and has_mutating:
            self._add(
                rule.rule_id,
                node,
                MESSAGES["TMP003"].format(
                    header="methods=['GET', ...]", path=path
                ),
            )

    def _inspect_request_call(self, node: ast.Call) -> None:
        """Check for parameter tampering and method override header reading."""
        self._inspect_override_headers(node)
        self._inspect_sensitive_params(node)

    def _inspect_override_headers(self, node: ast.Call) -> None:
        """Flag reads of X-HTTP-Method-Override headers (TMP003)."""
        rule = self._rule("TMP003")
        if rule is None:
            return

        name = _call_name(node).lower()
        if name not in {"get", "get_header", "headers"}:
            return

        for arg in _call_arguments(node):
            val = _string_value(arg)
            if val and val.lower() in _OVERRIDE_HEADERS:
                self._add(
                    rule.rule_id,
                    node,
                    MESSAGES["TMP003"].format(
                        header=val, path=_call_name(node)
                    ),
                )
                return

    def _inspect_sensitive_params(self, node: ast.Call) -> None:
        """Flag reads of sensitive financial/role parameters from client input (TMP002)."""
        rule = self._rule("TMP002")
        if rule is None:
            return

        name = _call_name(node).lower()
        if name != "get":
            return

        # Ensure receiver is request-related (form, json, cookies, values, args)
        if isinstance(node.func, ast.Attribute):
            rec = _dotted_name(node.func.value).lower()
            if not any(token in rec for token in ("form", "json", "cookies", "values")):
                return

        for arg in _call_arguments(node):
            val = _string_value(arg)
            if val and val.lower() in _SENSITIVE_PARAM_NAMES:
                self._add(
                    rule.rule_id,
                    node,
                    MESSAGES["TMP002"].format(
                        param=val, sink=_call_name(node)
                    ),
                )
                return


def _name() -> str:
    """Return the analyzer identifier used for rule lookup."""
    return ANALYZER_NAME


def _analyze(target: SourceFile) -> list:
    """Analyze one parsed source file for tampering and rate-limiting issues."""
    rules = _rules_for(ANALYZER_NAME)
    if not rules:
        return []
    return TamperVisitor(target, rules)._run()
