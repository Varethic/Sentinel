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


def _parse_constraint(description: str) -> tuple[str, str, str] | None:
    """Parse 'Affects <pkg> (<op><ver>)' from rule description."""
    idx = description.lower().rfind("affects ")
    if idx == -1:
        return None
    part = description[idx + len("affects "):].strip().rstrip(".")
    if "(" in part and ")" in part:
        pkg, _, rest = part.partition("(")
        pkg = pkg.strip().lower()
        constraint = rest.rstrip(")").strip()
        op = ""
        ver = ""
        for i, ch in enumerate(constraint):
            if ch in "<>=":
                op += ch
            else:
                ver = constraint[i:].strip()
                break
        if op and ver:
            return pkg, op, ver
    return None


def _parse_version(v_str: str) -> tuple[int, ...]:
    """Extract numeric components from a version string."""
    nums: list[int] = []
    current = ""
    for ch in v_str:
        if ch.isdigit():
            current += ch
        else:
            if current:
                nums.append(int(current))
                current = ""
    if current:
        nums.append(int(current))
    return tuple(nums)


def _version_matches(detected: str, op: str, constraint: str) -> bool:
    """Compare detected version against constraint operator."""
    v_det = _parse_version(detected)
    v_con = _parse_version(constraint)
    if not v_det or not v_con:
        return False
    max_len = max(len(v_det), len(v_con))
    p_det = v_det + (0,) * (max_len - len(v_det))
    p_con = v_con + (0,) * (max_len - len(v_con))
    if op == "<":
        return p_det < p_con
    if op == "<=":
        return p_det <= p_con
    if op in ("=", "=="):
        return p_det == p_con
    if op == ">":
        return p_det > p_con
    if op == ">=":
        return p_det >= p_con
    return False


def _extract_product_versions(header_name: str, header_val: str) -> list[tuple[str, str]]:
    """Extract (product, version) pairs from response headers."""
    h_lower = header_name.lower()
    val = header_val.strip()
    if not val:
        return []

    # Dedicated version headers where product is implied by header name
    if h_lower in ("x-jenkins", "x-aspnet-version", "x-runtime"):
        first_char = val[0] if val else ""
        if first_char.isdigit():
            prod = "jenkins" if "jenkins" in h_lower else ("aspnet" if "aspnet" in h_lower else h_lower)
            v = val.split()[0].strip()
            return [(prod, v)]

    results: list[tuple[str, str]] = []
    cleaned = val.replace(",", " ").replace(";", " ")
    tokens = cleaned.split()
    i = 0
    while i < len(tokens):
        token = tokens[i].strip("()")
        if "/" in token:
            prod, _, ver = token.partition("/")
            prod = prod.strip()
            ver = ver.strip()
            if prod and ver and ver[0].isdigit():
                results.append((prod.lower(), ver))
        elif i + 1 < len(tokens):
            next_token = tokens[i + 1].strip("()")
            if token and next_token and next_token[0].isdigit():
                results.append((token.lower(), next_token))
                i += 1
        i += 1
    return results


def _match_product(prod: str, aliases: set[str]) -> bool:
    """Check if detected product name matches any rule alias."""
    prod_clean = prod.replace("-", "").replace(".", "").replace("_", "")
    for a in aliases:
        a_clean = a.replace("-", "").replace(".", "").replace("_", "")
        if prod == a or prod_clean == a_clean:
            return True
    return False


def _match_stack_cves(
    headers: dict[str, str],
    body: str,
    discovered_paths: list[str] | None = None,
) -> list[tuple[Rule, str]]:
    """Correlate HTTP response headers and path exposures with curated CVEs."""
    rules = _rules_for(ANALYZER_NAME)
    matches: list[tuple[Rule, str]] = []
    lowered_body = body.lower() if body else ""
    paths = [p.lower() for p in (discovered_paths or [])]

    # Extract explicit (product, version) pairs from headers
    detected_versions: list[tuple[str, str, str]] = []
    for hname, hval in headers.items():
        pairs = _extract_product_versions(hname, hval)
        for prod, ver in pairs:
            detected_versions.append((hname, prod, ver))

    for rule in rules:
        matched_rule = False

        # Header correlation requires explicit version matching
        if detected_versions:
            c_info = _parse_constraint(rule.description)
            if c_info:
                target_pkg, op, target_ver = c_info
                aliases = {target_pkg, target_pkg.replace("-", "").replace(".", "")}
                rule_hdrs = rule.patterns._get("headers", [])
                if isinstance(rule_hdrs, list):
                    for h in rule_hdrs:
                        h_str = str(h).lower()
                        if ":" in h_str:
                            val_part = h_str.partition(":")[2].strip().split("/")[0].strip()
                            if val_part:
                                aliases.add(val_part)
                        else:
                            aliases.add(h_str)

                for hname, prod, ver in detected_versions:
                    if _match_product(prod, aliases):
                        if _version_matches(ver, op, target_ver):
                            matches.append(
                                (
                                    rule,
                                    f"header '{hname}: {headers[hname]}' version {ver} matches {rule.cve} ({rule.name})",
                                )
                            )
                            matched_rule = True
                            break

        if matched_rule:
            continue

        # Check paths
        rule_paths = rule.patterns._get("paths", [])
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
