"""SARIF v2.1.0 structured reporter for GitHub Code Scanning and IDEs."""

from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from src.core.engine import AnalysisResult, Finding
from src.core.loader import Rule, Severity, _load_all

SARIF_SCHEMA: str = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
)
SARIF_VERSION: str = "2.1.0"
TOOL_NAME: str = "sentinel-auditor"
TOOL_VERSION: str = "0.1.0"
TOOL_URI: str = "https://github.com/Varethic/Sentinel"


def _sarif_level(severity: Severity) -> str:
    """Map Sentinel severity to SARIF result level."""
    if severity in (Severity.CRITICAL, Severity.HIGH):
        return "error"
    if severity is Severity.MEDIUM:
        return "warning"
    return "note"


def _rule_descriptor(rule: Rule) -> dict[str, Any]:
    """Serialize a Rule into a SARIF reportingDescriptor object."""
    tags = ["security", *rule.tags]
    if rule.cwe_id:
        tags.append(rule.cwe_id.lower())

    return {
        "id": rule.rule_id,
        "name": rule.name,
        "shortDescription": {"text": rule.name},
        "fullDescription": {"text": rule.description},
        "defaultConfiguration": {
            "level": _sarif_level(rule.severity),
        },
        "help": {
            "text": f"{rule.description}\n\nRemediation:\n{rule.remediation_example}",
        },
        "properties": {
            "tags": tags,
            "cwe": rule.cwe_id,
            "cve": rule.cve,
            "cve_date": rule.cve_date,
            "category": rule.category,
            "precision": "high",
        },
    }


def _result_object(finding: Finding, target_root: Path | None = None) -> dict[str, Any]:
    """Serialize a Finding into a SARIF result object."""
    file_path = finding.file_path.replace("\\", "/")
    if target_root is not None:
        try:
            rel = Path(finding.file_path).relative_to(target_root)
            file_path = str(rel).replace("\\", "/")
        except ValueError:
            pass

    line_number = max(1, finding.line_number)
    column_number = max(1, finding.column)

    return {
        "ruleId": finding.rule_id,
        "level": _sarif_level(finding.severity),
        "message": {"text": finding.message},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": file_path,
                    },
                    "region": {
                        "startLine": line_number,
                        "startColumn": column_number,
                    },
                }
            }
        ],
        "properties": {
            "cwe": finding.cwe_id,
            "cve": finding.cve,
            "cve_date": finding.cve_date,
            "category": finding.category,
            "remediation": finding.remediation,
        },
    }


def _sarif_report(
    result: AnalysisResult,
    target: Path | None = None,
    rules: Sequence[Rule] | None = None,
) -> dict[str, Any]:
    """Build the complete SARIF v2.1.0 document dictionary."""
    if rules is None:
        docs = _load_all()
        loaded_rules: list[Rule] = []
        for doc in docs.values():
            loaded_rules.extend(doc.rules)
    else:
        loaded_rules = list(rules)

    rule_descriptors = [_rule_descriptor(r) for r in loaded_rules]
    results = [_result_object(f, target) for f in result.findings]

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "version": TOOL_VERSION,
                        "informationUri": TOOL_URI,
                        "rules": rule_descriptors,
                    }
                },
                "results": results,
            }
        ],
    }


def _render_sarif(
    result: AnalysisResult,
    target: Path | None = None,
    rules: Sequence[Rule] | None = None,
    indent: int = 2,
) -> str:
    """Render an analysis result as a formatted SARIF JSON string."""
    return json.dumps(_sarif_report(result, target, rules), indent=indent)
