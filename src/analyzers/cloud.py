"""Cloud storage and subdomain takeover static & surface analyzer (CLD001-CLD002).

Detection is purely static and non-destructive: it inspects Python source code for
hardcoded public cloud storage bucket URLs (CLD001), and web surface markup for external
references to cloud PaaS hostnames prone to subdomain takeover (CLD002).

No cloud bucket or external host is contacted. The analyzer only inspects local
source code and already-retrieved passive HTML markup.
"""

from __future__ import annotations

import ast
import re
from urllib.parse import urlparse

from src.core.engine import (
    SourceFile,
    Visitor,
)
from src.core.loader import _rules_for

ANALYZER_NAME: str = "cloud"

MESSAGES: dict[str, str] = {
    "CLD001": (
        "hardcoded public cloud storage bucket URL {url} found in source; "
        "enables direct unauthenticated access or bucket exposure"
    ),
    "CLD002": (
        "external asset reference points to takeover-prone cloud domain '{host}'; "
        "vulnerable to dangling subdomain takeover if abandoned"
    ),
}

_PUBLIC_BUCKET_DOMAINS: tuple[str, ...] = (
    "s3.amazonaws.com",
    "storage.googleapis.com",
    "blob.core.windows.net",
    "digitaloceanspaces.com",
)

_TAKEOVER_DOMAINS: tuple[str, ...] = (
    "herokuapp.com",
    "github.io",
    "azurewebsites.net",
    "s3.amazonaws.com",
    "pantheonsite.io",
    "firebaseapp.com",
    "surge.sh",
)

_BUCKET_URL_REGEX = re.compile(
    r"""https?://[a-zA-Z0-9.\-_]+(?:\.s3\.amazonaws\.com|storage\.googleapis\.com/[a-zA-Z0-9.\-_]+|\.blob\.core\.windows\.net)""",
    re.IGNORECASE,
)


def _is_public_bucket_url(text: str) -> bool:
    """Return True if text contains a hardcoded public cloud bucket URL."""
    if not (text.startswith("http://") or text.startswith("https://") or text.startswith("s3://")):
        return False
    lowered = text.lower()
    return any(domain in lowered for domain in _PUBLIC_BUCKET_DOMAINS)


def _check_subdomain_takeover(url_or_host: str) -> str | None:
    """Check if an external URL or host points to an unclaimed-prone PaaS domain."""
    cleaned = url_or_host.strip()
    if "://" in cleaned:
        parsed = urlparse(cleaned)
        host = (parsed.hostname or "").lower()
    else:
        host = cleaned.lower().split("/")[0].split(":")[0]

    for domain in _TAKEOVER_DOMAINS:
        if host.endswith(f".{domain}"):
            return host
    return None


def _evaluate_takeover_surface(urls: list[str]) -> list[str]:
    """Inspect markup links and subresources for takeover-prone cloud hosts."""
    reasons: list[str] = []
    seen: set[str] = set()
    for item in urls:
        host = _check_subdomain_takeover(item)
        if host and host not in seen:
            seen.add(host)
            reasons.append(f"external resource points to takeover-prone host: {host}")
    return reasons


class CloudVisitor(Visitor):
    """AST visitor for hardcoded public cloud storage buckets."""

    def visit_Constant(self, node: ast.Constant) -> None:
        """Inspect string constants for hardcoded public cloud bucket URLs."""
        if isinstance(node.value, str):
            self._inspect_string(node, node.value)
        self.generic_visit(node)

    def _inspect_string(self, node: ast.AST, text: str) -> None:
        """Flag strings containing public cloud storage bucket URLs (CLD001)."""
        rule = self._rule("CLD001")
        if rule is None:
            return

        if not _is_public_bucket_url(text):
            return

        display = text if len(text) <= 60 else text[:57] + "..."
        self._add(
            rule.rule_id,
            node,
            MESSAGES["CLD001"].format(url=repr(display)),
        )


def _name() -> str:
    """Return the analyzer identifier used for rule lookup."""
    return ANALYZER_NAME


def _analyze(target: SourceFile) -> list:
    """Analyze one parsed source file for hardcoded cloud storage issues."""
    rules = _rules_for(ANALYZER_NAME)
    if not rules:
        return []
    return CloudVisitor(target, rules)._run()
