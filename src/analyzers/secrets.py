"""Hardcoded secrets and weak cryptography static analyzer (SEC001-SEC003).

Detection is purely static. It inspects module-level and function-level
assignments for credential-looking names bound to real string literals, calls to
broken hash functions, and use of the non-cryptographic ``random`` module for
values that are then treated as security tokens.

The analyzer is intentionally conservative about what counts as a secret so that
ordinary configuration constants do not produce noise.
"""

from __future__ import annotations

import ast

from src.core.engine import (
    SourceFile,
    Visitor,
    _call_name,
    _dotted_name,
    _iter_subexpressions,
    _string_value,
)
from src.core.loader import Rule, _rules_for

ANALYZER_NAME: str = "secrets"

MESSAGES: dict[str, str] = {
    "SEC001": (
        "sensitive name {name} is assigned a hardcoded string literal; "
        "move it to an environment variable or secret store"
    ),
    "SEC002": (
        "weak hash function {sink}() is used for a security value; "
        "MD5 and SHA-1 have practical collision attacks"
    ),
    "SEC003": (
        "non-cryptographic random source {sink}() feeds a security value ({name}); "
        "use the secrets module"
    ),
}

WEAK_HASH_SINKS: frozenset[str] = frozenset({"md5", "sha1", "md4", "sha"})

RANDOM_SINKS: frozenset[str] = frozenset(
    {
        "random",
        "randint",
        "randrange",
        "choice",
        "choices",
        "getrandbits",
        "sample",
        "shuffle",
        "uniform",
        "randbytes",
    }
)

DEFAULT_PLACEHOLDERS: frozenset[str] = frozenset(
    {
        "",
        "changeme",
        "change_me",
        "change-me",
        "example",
        "placeholder",
        "your_secret_here",
        "your-key-here",
        "xxx",
        "todo",
        "none",
        "null",
        "redacted",
        "dummy",
        "test",
        "fake",
        "secret",
        "password",
        "<your-key>",
        "${secret_key}",
    }
)

DEFAULT_NAME_TOKENS: tuple[str, ...] = (
    "api_key",
    "apikey",
    "secret",
    "secret_key",
    "password",
    "passwd",
    "pwd",
    "token",
    "access_key",
    "private_key",
    "aws_secret",
    "jwt_secret",
    "client_secret",
    "auth_key",
)

DEFAULT_MIN_LENGTH: int = 4

METADATA_SUFFIXES: tuple[str, ...] = (
    "_env",
    "_var",
    "_name",
    "_file",
    "_path",
    "_header",
    "_field",
    "_param",
    "_type",
    "_url",
    "_regex",
    "_pattern",
    "_hint",
    "_label",
    "_help",
    "_prompt",
    "_key_name",
)


def _name_tokens(rule: Rule) -> tuple[str, ...]:
    """Return the configured sensitive-name fragments for a rule."""
    configured = tuple(token.lower() for token in rule.patterns._strings("name_tokens"))
    return configured or DEFAULT_NAME_TOKENS


def _placeholder_values(rule: Rule) -> frozenset[str]:
    """Return the configured placeholder literals that are not secrets."""
    configured = {value.lower() for value in rule.patterns._strings("placeholder_values")}
    return frozenset(configured) | DEFAULT_PLACEHOLDERS


def _min_length(rule: Rule) -> int:
    """Return the minimum literal length before a value counts as a secret."""
    raw = rule.patterns._get("min_length", DEFAULT_MIN_LENGTH)
    try:
        return int(raw)
    except (TypeError, ValueError):
        return DEFAULT_MIN_LENGTH


def _is_metadata_name(name: str) -> bool:
    """Return True when a name describes a credential rather than holding one."""
    lowered = name.lower()
    return any(lowered.endswith(suffix) for suffix in METADATA_SUFFIXES)


def _target_name(node: ast.AST) -> str:
    """Return the assigned variable name for a simple or annotated target."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return ""


def _strip_calls(node: ast.AST) -> ast.AST:
    """Unwrap trivial wrapper calls so the literal underneath is visible."""
    current = node
    while isinstance(current, ast.Call) and current.args:
        current = current.args[0]
    return current


def _dynamic_env_assignment(value: ast.AST) -> bool:
    """Return True when a value is loaded from the environment or config."""
    for child in _iter_subexpressions(value):
        if isinstance(child, ast.Call):
            name = _call_name(child)
            if name in {"getenv", "get"}:
                return True
            dotted = _dotted_name(child).lower()
            if dotted.startswith(("os.environ", "os.getenv")):
                return True
        if isinstance(child, ast.Attribute):
            dotted = _dotted_name(child).lower()
            if dotted.startswith(("os.environ", "config.", "settings.")):
                return True
    return False


def _looks_sensitive(name: str, tokens: tuple[str, ...]) -> bool:
    """Return True when a variable name marks it as credential-bearing."""
    if not name or _is_metadata_name(name):
        return False
    lowered = name.lower()
    return any(token in lowered for token in tokens)


def _is_real_literal(value: ast.AST, placeholders: frozenset[str], minimum: int) -> str | None:
    """Return the literal text when it looks like a genuine hardcoded secret."""
    text = _string_value(_strip_calls(value))
    if text is None:
        return None
    stripped = text.strip()
    if len(stripped) < minimum:
        return None
    if stripped.lower() in placeholders:
        return None
    if stripped.startswith(("{", "<", "__")) or stripped.endswith("..."):
        return None
    if stripped.isupper() and "_" in stripped and " " not in stripped:
        return None
    if not any(char.isalnum() for char in stripped):
        return None
    return stripped


def _use_names(value: ast.AST) -> set[str]:
    """Return every identifier referenced inside an expression."""
    names: set[str] = set()
    for child in _iter_subexpressions(value):
        if isinstance(child, ast.Name):
            names.add(child.id)
        elif isinstance(child, ast.Attribute):
            names.add(child.attr)
    return names


def _random_origin(node: ast.Call) -> bool:
    """Return True when a call originates from the ``random`` module."""
    dotted = _dotted_name(node.func).lower()
    if dotted == "random" or dotted.startswith("random."):
        return True
    name = _call_name(node)
    return name in RANDOM_SINKS


class SecretsVisitor(Visitor):
    """AST visitor implementing the secrets and weak-crypto rules."""

    def visit_Assign(self, node: ast.Assign) -> None:
        """Inspect simple assignments for hardcoded credentials."""
        self._inspect_assignment(node.targets, node.value, node)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        """Inspect annotated assignments (``NAME: str = "value"``)."""
        if node.value is not None:
            self._inspect_assignment([node.target], node.value, node)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        """Inspect weak hash construction and insecure random usage."""
        self._inspect_weak_hash(node)
        self._inspect_random(node)
        self.generic_visit(node)

    def _inspect_assignment(
        self,
        targets: list[ast.AST],
        value: ast.AST,
        node: ast.AST,
    ) -> None:
        """Report a hardcoded secret assignment when one is present."""
        rule = self._rule("SEC001")
        if rule is None:
            return
        if _dynamic_env_assignment(value):
            return
        tokens = _name_tokens(rule)
        placeholders = _placeholder_values(rule)
        minimum = _min_length(rule)

        for target in targets:
            name = _target_name(target)
            if not name or not _looks_sensitive(name, tokens):
                continue
            literal = _is_real_literal(value, placeholders, minimum)
            if literal is None:
                continue
            self._add("SEC001", node, MESSAGES["SEC001"].format(name=name))
            return

    def _inspect_weak_hash(self, node: ast.Call) -> None:
        """Report hashlib.md5()/sha1() unless usedforsecurity=False is set."""
        rule = self._rule("SEC002")
        if rule is None:
            return
        sink = _call_name(node)
        sinks = {item.lower() for item in rule.patterns._strings("sinks")}
        if sink not in (sinks or WEAK_HASH_SINKS):
            return

        dotted = _dotted_name(node.func).lower()
        if dotted and not dotted.startswith(("hashlib.", "crypt.", "_md5", "_sha1")):
            if sink not in WEAK_HASH_SINKS:
                return
            if "." in dotted and not dotted.startswith(("hashlib", "crypt")):
                return

        safe_keywords = {item.lower() for item in rule.patterns._strings("safe_keywords")}
        for keyword in node.keywords:
            if keyword.arg is None:
                continue
            if keyword.arg.lower() not in (safe_keywords or {"usedforsecurity"}):
                continue
            if isinstance(keyword.value, ast.Constant) and keyword.value.value is False:
                return

        self._add("SEC002", node, MESSAGES["SEC002"].format(sink=sink))

    def _inspect_random(self, node: ast.Call) -> None:
        """Report random-module values that feed a security-sensitive name."""
        rule = self._rule("SEC003")
        if rule is None:
            return
        if not _random_origin(node):
            return
        tokens = tuple(item.lower() for item in rule.patterns._strings("security_tokens"))
        wanted = tokens or (
            "token",
            "password",
            "secret",
            "session",
            "nonce",
            "csrf",
            "otp",
            "salt",
        )
        name = self._security_context(node, wanted)
        if not name:
            return
        self._add(
            "SEC003",
            node,
            MESSAGES["SEC003"].format(sink=_call_name(node), name=name),
        )

    def _security_context(self, node: ast.Call, tokens: tuple[str, ...]) -> str:
        """Return the enclosing identifier when it is security-named, else ''."""
        for parent in self._parents_of(node):
            if isinstance(parent, (ast.Assign, ast.AnnAssign)):
                targets = parent.targets if isinstance(parent, ast.Assign) else [parent.target]
                for target in targets:
                    name = _target_name(target)
                    if name and _matches_token(name, tokens):
                        return name
            if isinstance(parent, (ast.Return, ast.keyword)):
                value = parent.value if isinstance(parent, ast.Return) else parent.value
                if isinstance(value, ast.Call) and value is node:
                    for ancestor in self._parents_of(parent):
                        if isinstance(ancestor, (ast.FunctionDef, ast.AsyncFunctionDef)):
                            if _matches_token(ancestor.name, tokens):
                                return ancestor.name
            if isinstance(parent, ast.Call):
                func_name = _call_name(parent)
                if _matches_token(func_name, tokens):
                    return func_name
        return ""

    def _parents_of(self, node: ast.AST) -> list[ast.AST]:
        """Return the ancestor chain of a node, nearest first."""
        parents: list[ast.AST] = []
        for candidate in ast.walk(self._target.tree):
            if not isinstance(candidate, ast.AST):
                continue
            for child in ast.iter_child_nodes(candidate):
                if child is node:
                    parents.append(candidate)
        return parents


def _matches_token(name: str, tokens: tuple[str, ...]) -> bool:
    """Return True when an identifier contains one of the security tokens."""
    lowered = name.lower()
    return any(token in lowered for token in tokens)


def _name() -> str:
    """Return the analyzer identifier used for rule lookup."""
    return ANALYZER_NAME


def _analyze(target: SourceFile) -> list:
    """Analyze one parsed source file for secrets and weak crypto."""
    rules = _rules_for(ANALYZER_NAME)
    if not rules:
        return []
    return SecretsVisitor(target, rules)._run()


def _is_sensitive_name(name: str, tokens: tuple[str, ...] | None = None) -> bool:
    """Expose the sensitive-name heuristic for callers and tests."""
    return _looks_sensitive(name, tokens or DEFAULT_NAME_TOKENS)


def _placeholder_set() -> frozenset[str]:
    """Expose the placeholder literal set for callers and tests."""
    return DEFAULT_PLACEHOLDERS
