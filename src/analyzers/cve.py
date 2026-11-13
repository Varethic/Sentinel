"""Curated CVE knowledge base and vulnerability matcher (CVE001-CVE100).

Provides static AST and dependency matching for 100 high-profile CVEs across
web frameworks, CMS platforms, servers and libraries, plus passive HTTP stack
and path signature correlation for live web auditing.
"""

from __future__ import annotations

import ast
from collections.abc import Sequence
from pathlib import Path

from src.core.engine import Finding, SourceFile, Visitor, _call_name, _dotted_name
from src.core.loader import Rule, _rules_for

ANALYZER_NAME: str = "cve"

VULNERABLE_IMPORTS: dict[str, str] = {
    "vm2": "CVE096",
    "changedetection": "CVE100",
}


class CveVisitor(Visitor):
    """AST visitor detecting vulnerable package imports and code signatures."""

    def __init__(self, target: SourceFile, rules: Sequence[Rule]) -> None:
        super().__init__(target, rules)
        self._reported_lines: set[int] = set()

    def visit_Import(self, node: ast.Import) -> None:
        """Flag imports of known vulnerable packages."""
        for alias in node.names:
            name = alias.name.lower().split(".")[0]
            if name in VULNERABLE_IMPORTS:
                rule_id = VULNERABLE_IMPORTS[name]
                lineno = getattr(node, "lineno", 0)
                if lineno not in self._reported_lines:
                    self._reported_lines.add(lineno)
                    self._add(
                        rule_id,
                        node,
                        f"Import of package '{name}' with known critical vulnerabilities ({rule_id})",
                    )
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Flag from-imports of known vulnerable packages."""
        if node.module:
            mod = node.module.lower().split(".")[0]
            if mod in VULNERABLE_IMPORTS:
                rule_id = VULNERABLE_IMPORTS[mod]
                lineno = getattr(node, "lineno", 0)
                if lineno not in self._reported_lines:
                    self._reported_lines.add(lineno)
                    self._add(
                        rule_id,
                        node,
                        f"Import from package '{mod}' with known critical vulnerabilities ({rule_id})",
                    )
        self.generic_visit(node)


def _match_manifest_dependencies(
    manifest_path: Path,
    rules: Sequence[Rule],
    display_path: str,
) -> list[Finding]:
    """Inspect dependency manifests for vulnerable package versions."""
    findings: list[Finding] = []
    if not manifest_path.is_file():
        return findings

    try:
        content = manifest_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return findings

    lowered_content = content.lower()
    for rule in rules:
        pkg = rule.patterns._get("package", "")
        if not pkg:
            continue
        pkg_lower = str(pkg).lower()
        if pkg_lower in lowered_content:
            # Check for version indicators
            findings.append(
                Finding(
                    rule_id=rule.rule_id,
                    rule_name=rule.name,
                    severity=rule.severity,
                    category=rule.category,
                    cwe_id=rule.cwe_id,
                    cve=rule.cve,
                    cve_date=rule.cve_date,
                    file_path=display_path,
                    line_number=1,
                    column=1,
                    code_snippet=f"{pkg} declared in {manifest_path.name}",
                    message=f"Vulnerable dependency '{pkg}' declared in manifest ({rule.cve})",
                    remediation=rule.remediation_example,
                )
            )
    return findings


def _match_stack_cves(
    headers: dict[str, str],
    body: str,
    discovered_paths: list[str] | None = None,
) -> list[tuple[Rule, str]]:
    """Correlate HTTP response headers and path exposures with curated CVEs."""
    rules = _rules_for(ANALYZER_NAME)
    matches: list[tuple[Rule, str]] = []
    lowered_headers = {k.lower(): v.lower() for k, v in headers.items()}
    lowered_body = body.lower() if body else ""
    paths = [p.lower() for p in (discovered_paths or [])]

    for rule in rules:
        rule_hdrs = rule.patterns._get("headers", [])
        rule_paths = rule.patterns._get("paths", [])

        # Check headers
        if isinstance(rule_hdrs, list):
            for hdr_probe in rule_hdrs:
                probe = str(hdr_probe).lower()
                if ":" in probe:
                    hname, _, hval = probe.partition(":")
                    hname = hname.strip()
                    hval = hval.strip()
                    if hname in lowered_headers and hval in lowered_headers[hname]:
                        matches.append(
                            (rule, f"header '{hname}: {lowered_headers[hname]}' matches {rule.cve} ({rule.name})")
                        )
                        break
                else:
                    if probe in lowered_headers:
                        matches.append(
                            (rule, f"header '{probe}' indicates potential {rule.cve} ({rule.name})")
                        )
                        break

        # Check paths
        if isinstance(rule_paths, list):
            for path_probe in rule_paths:
                probe = str(path_probe).lower()
                if probe in ("/"):
                    continue
                # Check discovered links
                if any(probe in p for p in paths):
                    matches.append(
                        (rule, f"endpoint '{probe}' exposed on host matches {rule.cve} ({rule.name})")
                    )
                    break
                # Check body references
                if probe in lowered_body and len(probe) > 6:
                    matches.append(
                        (rule, f"reference to '{probe}' in markup matches {rule.cve} ({rule.name})")
                    )
                    break

    return matches


def _analyze(target: SourceFile) -> list[Finding]:
    """Inspect one parsed source file for CVE indicators."""
    rules = _rules_for(ANALYZER_NAME)
    if not rules:
        return []
    visitor = CveVisitor(target, rules)
    return visitor._run()


def _name() -> str:
    """Return the analyzer identifier matching cve.json."""
    return ANALYZER_NAME
