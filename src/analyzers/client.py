"""Client-side storage and reverse tabnabbing static & surface analyzer (CLT001-CLT002).

Detection is purely static: it inspects HTML markup and inline client scripts for
sensitive credentials stored in localStorage/sessionStorage (CLT001), and external
links with target="_blank" lacking rel="noopener" or rel="noreferrer" (CLT002).

No JavaScript execution or browser automation is performed. The analyzer only
evaluates static strings and already-retrieved passive HTML documents.
"""

from __future__ import annotations

import ast
import re
from urllib.parse import urlparse

from src.core.engine import (
    SourceFile,
    Visitor,
)
from src.core.loader import Rule, _rules_for

ANALYZER_NAME: str = "client"

MESSAGES: dict[str, str] = {
    "CLT001": (
        "sensitive credential or token '{token}' stored in client-side storage "
        "via {sink}; credentials in web storage are vulnerable to theft via XSS"
    ),
    "CLT002": (
        "external target='_blank' link '{href}' is missing rel='noopener' or "
        "rel='noreferrer'; vulnerable to reverse tabnabbing"
    ),
}

_SENSITIVE_STORAGE_KEYS: frozenset[str] = frozenset(
    {
        "token",
        "jwt",
        "auth",
        "secret",
        "password",
        "access_token",
        "api_key",
        "session_token",
        "id_token",
        "refresh_token",
    }
)

_STORAGE_REGEX = re.compile(
    r"""(?:localStorage|sessionStorage)\.setItem\s*\(\s*['"]([^'"]+)['"]""",
    re.IGNORECASE,
)

_BLANK_LINK_REGEX = re.compile(
    r"""<a\b[^>]*target=["']_blank["'][^>]*>""",
    re.IGNORECASE,
)


def _check_client_storage_text(text: str) -> list[str]:
    """Return sensitive keys found inside localStorage/sessionStorage calls."""
    matches: list[str] = []
    for match in _STORAGE_REGEX.finditer(text):
        key = match.group(1).lower()
        if any(token in key for token in _SENSITIVE_STORAGE_KEYS):
            matches.append(match.group(1))
    return matches


def _is_external_link(href: str, base_url: str) -> bool:
    """Return True if href points to an external third-party origin."""
    if not (href.startswith("http://") or href.startswith("https://")):
        return False
    if not base_url:
        return True
    parsed_base = urlparse(base_url)
    parsed_href = urlparse(href)
    return (parsed_base.netloc or "").lower() != (parsed_href.netloc or "").lower()


def _evaluate_tabnabbing_surface(
    links_with_attrs: list[dict[str, str]], base_url: str
) -> list[str]:
    """Inspect markup links for target=_blank without rel=noopener."""
    reasons: list[str] = []
    seen: set[str] = set()
    for item in links_with_attrs:
        href = item.get("href", "").strip()
        target = item.get("target", "").lower().strip()
        rel = item.get("rel", "").lower().strip()
        if target != "_blank":
            continue
        if not _is_external_link(href, base_url):
            continue
        if "noopener" not in rel and "noreferrer" not in rel:
            display = href if len(href) <= 50 else href[:47] + "..."
            if display not in seen:
                seen.add(display)
                reasons.append(
                    f"target=_blank link missing rel=noopener/noreferrer: {display}"
                )
    return reasons


def _evaluate_client_storage_surface(script_contents: list[str]) -> list[str]:
    """Inspect inline script blocks for sensitive tokens in client storage."""
    reasons: list[str] = []
    seen: set[str] = set()
    for code in script_contents:
        found = _check_client_storage_text(code)
        for token in found:
            if token not in seen:
                seen.add(token)
                reasons.append(
                    f"inline script stores '{token}' in localStorage/sessionStorage"
                )
    return reasons


class ClientVisitor(Visitor):
    """AST visitor for client-side storage leaks and reverse tabnabbing."""

    def visit_Constant(self, node: ast.Constant) -> None:
        """Inspect string constants for client-side storage and unpinned blank links."""
        if isinstance(node.value, str):
            self._inspect_string(node, node.value)
        self.generic_visit(node)

    def _inspect_string(self, node: ast.AST, text: str) -> None:
        """Evaluate string literals for client security issues."""
        self._inspect_storage(node, text)
        self._inspect_tabnabbing(node, text)

    def _inspect_storage(self, node: ast.AST, text: str) -> None:
        """Flag client storage of sensitive tokens (CLT001)."""
        rule = self._rule("CLT001")
        if rule is None:
            return

        found = _check_client_storage_text(text)
        for token in found:
            self._add(
                rule.rule_id,
                node,
                MESSAGES["CLT001"].format(token=token, sink="setItem()"),
            )
            return

    def _inspect_tabnabbing(self, node: ast.AST, text: str) -> None:
        """Flag raw HTML strings with unpinned target=_blank links (CLT002)."""
        rule = self._rule("CLT002")
        if rule is None:
            return

        if "<a" not in text.lower() or "target" not in text.lower():
            return

        for match in _BLANK_LINK_REGEX.finditer(text):
            tag = match.group(0).lower()
            if "rel=" not in tag or ("noopener" not in tag and "noreferrer" not in tag):
                self._add(
                    rule.rule_id,
                    node,
                    MESSAGES["CLT002"].format(href="target='_blank' link"),
                )
                return


def _name() -> str:
    """Return the analyzer identifier used for rule lookup."""
    return ANALYZER_NAME


def _analyze(target: SourceFile) -> list:
    """Analyze one parsed source file for client-side issues."""
    rules = _rules_for(ANALYZER_NAME)
    if not rules:
        return []
    return ClientVisitor(target, rules)._run()
