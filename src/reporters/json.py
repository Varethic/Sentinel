"""Structured JSON reporter for CI/CD integration."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from src.core.engine import AnalysisResult, Finding
from src.core.loader import Severity

SCHEMA_VERSION: str = "1.0.0"
TOOL_NAME: str = "sentinel-auditor"
TOOL_VERSION: str = "0.1.0"


def _timestamp() -> str:
    """Return an RFC 3339 UTC timestamp for report metadata."""
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def _finding_dict(finding: Finding) -> dict[str, Any]:
    """Serialize a single finding."""
    return {
        "rule_id": finding.rule_id,
        "rule_name": finding.rule_name,
        "severity": finding.severity.value,
        "category": finding.category,
        "cwe_id": finding.cwe_id,
        "location": {
            "file": finding.file_path,
            "line": finding.line_number,
            "column": finding.column,
        },
        "message": finding.message,
        "code_snippet": finding.code_snippet,
        "remediation": finding.remediation,
        "blocking": finding._is_blocking(),
    }


def _empty_counts() -> dict[str, int]:
    """Return a zeroed severity counter."""
    return {level.value: 0 for level in Severity}


def _count(findings: Sequence[Finding]) -> dict[str, int]:
    """Count findings per severity."""
    counts = _empty_counts()
    for finding in findings:
        counts[finding.severity.value] += 1
    return counts


def _envelope(
    report_type: str,
    target: str,
    findings: Sequence[Finding],
    extra: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Wrap findings in the common report envelope."""
    counts = _count(findings)
    blocking = sum(1 for finding in findings if finding._is_blocking())
    payload: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": TOOL_NAME, "version": TOOL_VERSION},
        "report_type": report_type,
        "generated_at": _timestamp(),
        "target": target,
        "summary": {
            "total": len(findings),
            "severity_counts": counts,
            "blocking": blocking,
            "passed": blocking == 0,
        },
        "findings": [_finding_dict(finding) for finding in findings],
    }
    if extra:
        payload.update(dict(extra))
    return payload


def _code_report(result: AnalysisResult, target: str) -> dict[str, Any]:
    """Build the JSON document for an audit-code run."""
    extra: dict[str, Any] = {
        "scan": {
            "files_scanned": result.files_scanned,
            "files_skipped": result.files_skipped,
            "errors": list(result.errors),
        }
    }
    return _envelope("code", target, result.findings, extra)


def _headers_report(report, target: str | None = None) -> dict[str, Any]:
    """Build the JSON document for an audit-headers run."""
    extra: dict[str, Any] = {
        "response": {
            "requested_url": report.url,
            "final_url": report.final_url,
            "status_code": report.status_code,
            "headers_present": list(report.present_headers),
            "cookies_observed": report.cookie_count,
            "errors": list(report.errors),
        }
    }
    return _envelope("headers", target or report.url, report.findings, extra)


def _dumps(payload: Mapping[str, Any], indent: int = 2) -> str:
    """Serialize a payload to JSON text."""
    return json.dumps(payload, indent=indent, sort_keys=False, ensure_ascii=False)


def _render_code(
    result: AnalysisResult,
    target: str,
    path: Path | None = None,
    indent: int = 2,
) -> str:
    """Serialize a code audit result, optionally writing it to disk."""
    text = _dumps(_code_report(result, target), indent=indent)
    if path is not None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text + "\n", encoding="utf-8")
    return text


def _render_headers(report, path: Path | None = None, indent: int = 2) -> str:
    """Serialize a header audit report, optionally writing it to disk."""
    text = _dumps(_headers_report(report), indent=indent)
    if path is not None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text + "\n", encoding="utf-8")
    return text


def _from_findings(
    findings: Sequence[Finding],
    target: str,
    report_type: str = "code",
) -> dict[str, Any]:
    """Build a report envelope from a bare list of findings."""
    return _envelope(report_type, target, findings)


def _validate(text: str) -> bool:
    """Return True when the given text is valid JSON (test helper)."""
    try:
        json.loads(text)
    except json.JSONDecodeError:
        return False
    return True


def _web_report(report, target: str | None = None) -> dict[str, Any]:
    """Build the JSON document for a unified URL check."""
    payload = _envelope("web", target or report.url, report.findings)
    payload["web"] = report._summary()
    payload["summary"]["verdict"] = report._verdict().value
    payload["summary"]["vulnerable_categories"] = payload["web"]["vulnerable"]
    payload["summary"]["needs_hardening"] = payload["web"]["needs_hardening"]
    payload["summary"]["passed"] = not report._has_blocking()
    return payload


def _render_web(report, path: Path | None = None, indent: int = 2) -> str:
    """Serialize a unified URL check, optionally writing it to disk."""
    text = _dumps(_web_report(report), indent=indent)
    if path is not None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text + "\n", encoding="utf-8")
    return text
