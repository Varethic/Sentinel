"""Authentication, TLS and debug configuration static analyzer (AUTH001-AUTH003).

Detection is purely static: it inspects HTTP client calls for disabled
certificate verification, JWT decode calls for skipped signature checks, and
debug-mode assignments or development-server launches.

No request is issued and no token is decoded here. The analyzer only reads
source text that the operator already owns.
"""

from __future__ import annotations

import ast

from src.core.engine import (
    SourceFile,
    Visitor,
    _call_name,
    _dotted_name,
)
from src.core.loader import _rules_for

ANALYZER_NAME: str = "auth"

MESSAGES: dict[str, str] = {
    "AUTH001": (
        "{sink}() disables TLS certificate verification via {setting}; "
        "any certificate is accepted, so the connection can be intercepted"
    ),
    "AUTH002": (
        "jwt.{sink}() runs with signature verification disabled; "
        "the token payload is trusted without proving its origin"
    ),
    "AUTH003": (
        "production debug mode enabled via {setting}; "
        "interactive tracebacks and configuration are exposed to visitors"
    ),
}

HTTP_MODULES: frozenset[str] = frozenset(
    {"requests", "httpx", "aiohttp", "urllib3", "http", "urllib"}
)

JWT_MODULES: frozenset[str] = frozenset({"jwt", "jose", "python_jose", "jwcrypto", "authlib"})

UNVERIFIED_HELPERS: frozenset[str] = frozenset(
    {"_create_unverified_context", "create_default_context"}
)

DEBUG_RUNNERS: frozenset[str] = frozenset({"run", "run_simple", "serve", "make_server", "runapi"})


def _keyword_bool(node: ast.Call, name: str) -> bool | None:
    """Return the boolean value of a keyword argument, or None if absent."""
    for keyword in node.keywords:
        if keyword.arg and keyword.arg.lower() == name.lower():
            value = keyword.value
            if isinstance(value, ast.Constant) and isinstance(value.value, bool):
                return value.value
    return None


def _mentions_http_module(dotted: str) -> bool:
    """Return True when a dotted name resolves into an HTTP client module."""
    lowered = dotted.lower()
    return any(part in HTTP_MODULES for part in lowered.split("."))


def _mentions_jwt_module(dotted: str) -> bool:
    """Return True when a dotted name resolves into a JWT library."""
    lowered = dotted.lower()
    return any(part in JWT_MODULES for part in lowered.split("."))


def _literal_false_dict(node: ast.AST) -> bool:
    """Return True for a dict literal containing a verify flag set to False."""
    if not isinstance(node, ast.Dict):
        return False
    for key, value in zip(node.keys, node.values, strict=False):
        if not isinstance(key, ast.Constant) or not isinstance(key.value, str):
            continue
        if not isinstance(value, ast.Constant) or value.value is not False:
            continue
        if "verify" in key.value.lower():
            return True
    return False


def _dict_has_false_key(node: ast.AST, tokens: frozenset[str]) -> str:
    """Return the key name of a dict entry set to False and matching tokens."""
    if not isinstance(node, ast.Dict):
        return ""
    for key, value in zip(node.keys, node.values, strict=False):
        if not isinstance(key, ast.Constant) or not isinstance(key.value, str):
            continue
        if not isinstance(value, ast.Constant) or value.value is not False:
            continue
        if key.value.lower() in tokens:
            return key.value
    return ""


class AuthVisitor(Visitor):
    """AST visitor implementing the authentication and TLS rules."""

    def visit_Call(self, node: ast.Call) -> None:
        """Inspect every call that may weaken TLS, JWT or debug settings."""
        self._inspect_call(node)
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        """Inspect assignments for a literal debug flag set to True."""
        self._inspect_assign(node)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        """Inspect annotated assignments for the same debug flag."""
        rule = self._rule("AUTH003")
        if (
            rule is not None
            and isinstance(node.value, ast.Constant)
            and node.value.value is True
            and self._is_debug_name(node.target)
        ):
            self._add(
                rule.rule_id,
                node,
                MESSAGES["AUTH003"].format(setting=f"{_dotted_name(node.target)} = True"),
            )
        self.generic_visit(node)

    def _is_debug_name(self, node: ast.AST) -> bool:
        """Return True when a target name reads as a debug flag."""
        return _dotted_name(node).upper() in {"DEBUG", "DEBUG_PROPAGATE_EXCEPTIONS"}

    def _inspect_assign(self, node: ast.Assign) -> None:
        """Flag ``DEBUG = True`` style assignments."""
        rule = self._rule("AUTH003")
        if rule is None:
            return
        if not isinstance(node.value, ast.Constant) or node.value.value is not True:
            return
        for target in node.targets:
            if self._is_debug_name(target):
                self._add(
                    rule.rule_id,
                    node,
                    MESSAGES["AUTH003"].format(setting=f"{_dotted_name(target)} = True"),
                )
                return

    def _inspect_call(self, node: ast.Call) -> None:
        """Evaluate one call node against all three auth rules."""
        name = _call_name(node)
        if not name:
            return

        if self._reports_unverified_tls(node, name):
            return
        if self._reports_jwt(node, name):
            return
        if self._reports_debug_runner(node, name):
            return

    def _reports_unverified_tls(self, node: ast.Call, name: str) -> bool:
        """verify=False on an HTTP call, or an unverified ssl context."""
        rule = self._rule("AUTH001")
        if rule is None:
            return False

        if name in UNVERIFIED_HELPERS:
            dotted = _dotted_name(node.func).lower()
            if "ssl" in dotted:
                self._add(
                    rule.rule_id,
                    node,
                    MESSAGES["AUTH001"].format(sink=name, setting=dotted),
                )
                return True

        dotted = _dotted_name(node.func)
        is_http = _mentions_http_module(dotted) or name in {
            sink.lower() for sink in rule.patterns._strings("sinks")
        }
        if not is_http:
            return False

        for keyword in node.keywords:
            if not keyword.arg:
                continue
            if keyword.arg.lower() not in {"verify", "verify_ssl", "check_hostname"}:
                continue
            value = keyword.value
            if isinstance(value, ast.Constant) and value.value is False:
                self._add(
                    rule.rule_id,
                    node,
                    MESSAGES["AUTH001"].format(sink=name, setting=f"{keyword.arg}=False"),
                )
                return True
        for argument in node.args:
            if isinstance(argument, ast.Dict) and _literal_false_dict(argument):
                self._add(
                    rule.rule_id,
                    node,
                    MESSAGES["AUTH001"].format(sink=name, setting="verify=False"),
                )
                return True
        return False

    def _reports_jwt(self, node: ast.Call, name: str) -> bool:
        """jwt.decode() with signature verification switched off."""
        rule = self._rule("AUTH002")
        if rule is None:
            return False
        sinks = {sink.lower() for sink in rule.patterns._strings("sinks")}
        if name not in sinks:
            return False
        if not _mentions_jwt_module(_dotted_name(node.func)):
            return False

        tokens = frozenset(token.lower() for token in rule.patterns._strings("unsafe_options"))

        for keyword in node.keywords:
            if not keyword.arg:
                continue
            lowered = keyword.arg.lower()
            if lowered == "options":
                setting = _dict_has_false_key(keyword.value, tokens)
                if setting:
                    self._add(
                        rule.rule_id,
                        node,
                        MESSAGES["AUTH002"].format(sink=name),
                    )
                    return True
            if lowered in {"verify", "verify_signature"}:
                value = keyword.value
                if isinstance(value, ast.Constant) and value.value is False:
                    self._add(
                        rule.rule_id,
                        node,
                        MESSAGES["AUTH002"].format(sink=name),
                    )
                    return True
        for argument in node.args:
            if isinstance(argument, ast.Dict) and _dict_has_false_key(argument, tokens):
                self._add(
                    rule.rule_id,
                    node,
                    MESSAGES["AUTH002"].format(sink=name),
                )
                return True
        return False

    def _reports_debug_runner(self, node: ast.Call, name: str) -> bool:
        """app.run(..., debug=True) / run_simple(..., debug=True)."""
        rule = self._rule("AUTH003")
        if rule is None:
            return False
        if name not in DEBUG_RUNNERS:
            return False
        if _keyword_bool(node, "debug") is True:
            self._add(
                rule.rule_id,
                node,
                MESSAGES["AUTH003"].format(setting="debug=True"),
            )
            return True
        return False


def _name() -> str:
    """Return the analyzer identifier used for rule lookup."""
    return ANALYZER_NAME


def _analyze(target: SourceFile) -> list:
    """Analyze one parsed source file for auth, TLS and debug issues."""
    rules = _rules_for(ANALYZER_NAME)
    if not rules:
        return []
    return AuthVisitor(target, rules)._run()
