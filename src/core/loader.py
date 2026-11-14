"""Rule loading, validation and lookup for the Sentinel auditor.

Static rule definitions live in ``src/json/*.json`` so that CWE/OWASP metadata,
detection patterns and remediation guidance stay decoupled from Python logic.
This module is the single place that turns those documents into typed objects.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from datetime import date
from enum import Enum
from functools import lru_cache
from pathlib import Path
from typing import Any

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)

RULE_DIRECTORY: Path = Path(__file__).resolve().parent.parent / "json"


class Severity(str, Enum):
    """Ordered severity levels used for reporting and exit codes."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    def _rank(self) -> int:
        """Return a sortable rank so severities can be ordered."""
        return _SEVERITY_ORDER[self]


_SEVERITY_ORDER: dict[Severity, int] = {
    Severity.LOW: 0,
    Severity.MEDIUM: 1,
    Severity.HIGH: 2,
    Severity.CRITICAL: 3,
}


class RuleLoadError(RuntimeError):
    """Raised when a rule document cannot be read, parsed or validated."""

    def __init__(self, source: str, reason: str) -> None:
        self.source = source
        self.reason = reason
        super().__init__(f"{source}: {reason}")


def _severity_of(value: str) -> Severity:
    """Coerce a case-insensitive severity string into a Severity member."""
    return Severity(value.strip().upper())


class RulePattern(BaseModel):
    """Analyzer-specific detection hints, kept deliberately permissive.

    The concrete meaning depends on the analyzer (AST sinks, header names,
    cookie attributes), so unknown keys are preserved instead of rejected.
    """

    model_config = ConfigDict(extra="allow", frozen=True)

    def _get(self, key: str, default: Any = None) -> Any:
        """Return a pattern option, tolerating documents that omit it."""
        return getattr(self, key, default)

    def _strings(self, key: str) -> list[str]:
        """Return a pattern option as a list of lowercase strings."""
        raw = self._get(key, [])
        if not isinstance(raw, list):
            return []
        return [str(item) for item in raw]

    def _sinks(self) -> frozenset[str]:
        """Names of calls/methods that act as dangerous sinks."""
        return frozenset(item.lower() for item in self._strings("sinks"))

    def _header(self) -> str | None:
        """Canonical (lowercase) header name targeted by a header rule."""
        raw = self._get("header")
        return str(raw).strip().lower() if raw else None


class Rule(BaseModel):
    """A single, fully validated detection rule."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    rule_id: str = Field(..., min_length=3, pattern=r"^[A-Z]{2,8}\d{3}$")
    name: str = Field(..., min_length=3, max_length=200)
    category: str = Field(..., min_length=3)
    cwe_id: str = Field(..., pattern=r"^CWE-\d+$")
    cve: str = Field(..., pattern=r"^CVE-\d{4}-\d{4,7}$")
    cve_date: str = Field(..., pattern=r"^\d{4}-\d{2}-\d{2}$")
    severity: Severity
    description: str = Field(..., min_length=10)
    remediation_example: str = Field(..., min_length=3)
    patterns: RulePattern = Field(default_factory=RulePattern)
    tags: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    enabled: bool = True

    @field_validator("cve_date")
    @classmethod
    def _check_cve_date(cls, value: str) -> str:
        """Reject impossible dates such as 2021-02-30 or month 13."""
        try:
            parsed = date.fromisoformat(value)
        except ValueError as exc:
            raise ValueError(f"not a valid calendar date: {value}") from exc
        if parsed.year < 1999:
            raise ValueError(f"CVE identifiers began in 1999, got {value}")
        return value

    def _is_enabled(self) -> bool:
        """Return whether the rule should participate in scans."""
        return bool(self.enabled)

    def _label(self) -> str:
        """Human readable identifier used in reports."""
        return f"{self.rule_id} {self.name}"

    def _cve_label(self) -> str:
        """Render the reference CVE with its publication date."""
        return f"{self.cve} ({self.cve_date})"

    def _fingerprint(self) -> tuple[str, str]:
        """Stable identity for de-duplicating identical findings."""
        return (self.rule_id, self.cwe_id)


class RuleSet(BaseModel):
    """A validated rule document (one JSON file) plus its metadata."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = Field(default="1.0.0")
    analyzer: str = Field(..., min_length=2)
    title: str = Field(..., min_length=3)
    rules: list[Rule] = Field(..., min_length=1)

    @field_validator("analyzer")
    @classmethod
    def _normalize_analyzer(cls, value: str) -> str:
        """Normalize the analyzer name to a lowercase identifier."""
        return value.strip().lower()

    @model_validator(mode="after")
    def _check_unique_rule_ids(self) -> RuleSet:
        """Reject documents that define the same rule_id twice."""
        seen: set[str] = set()
        for rule in self.rules:
            if rule.rule_id in seen:
                raise ValueError(f"duplicate rule_id {rule.rule_id!r}")
            seen.add(rule.rule_id)
        return self

    def _enabled_rules(self) -> list[Rule]:
        """Return only the rules enabled in the document."""
        return [rule for rule in self.rules if rule._is_enabled()]

    def _by_id(self, rule_id: str) -> Rule | None:
        """Look up a rule by its identifier."""
        for rule in self.rules:
            if rule.rule_id == rule_id:
                return rule
        return None


def _read_document(path: Path) -> dict[str, Any]:
    """Read and decode a JSON rule document from disk."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise RuleLoadError(str(path), f"cannot read file: {exc}") from exc

    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise RuleLoadError(str(path), f"invalid JSON at line {exc.lineno}: {exc.msg}") from exc

    if not isinstance(payload, dict):
        raise RuleLoadError(str(path), "top-level JSON value must be an object")
    return payload


def _load_ruleset(path: Path) -> RuleSet:
    """Load, decode and validate a single rule document into a RuleSet."""
    payload = _read_document(path)

    # Drop documentation-only keys that carry no runtime meaning.
    payload = {key: value for key, value in payload.items() if key != "$schema"}

    try:
        return RuleSet.model_validate(payload)
    except ValidationError as exc:
        details = "; ".join(
            f"{'.'.join(str(part) for part in error['loc'])}: {error['msg']}"
            for error in exc.errors()
        )
        raise RuleLoadError(str(path), f"schema validation failed: {details}") from exc


def _resolve_path(name: str, directory: Path | None = None) -> Path:
    """Resolve an analyzer name to its JSON document path."""
    base = directory or RULE_DIRECTORY
    candidate = base / f"{name}.json"
    if not candidate.is_file():
        raise RuleLoadError(str(candidate), "rule document not found")
    return candidate


@lru_cache(maxsize=None)
def _cached_ruleset(name: str) -> RuleSet:
    """Cached loader so repeated scans do not re-parse JSON documents."""
    return _load_ruleset(_resolve_path(name))


def _load_rules(name: str, directory: Path | None = None) -> RuleSet:
    """Public loader entry point for a named analyzer rule document."""
    if directory is None:
        return _cached_ruleset(name)
    return _load_ruleset(_resolve_path(name, directory))


def _load_all(directory: Path | None = None) -> dict[str, RuleSet]:
    """Load every rule document in the rule directory, keyed by analyzer."""
    base = directory or RULE_DIRECTORY
    if not base.is_dir():
        raise RuleLoadError(str(base), "rule directory not found")

    rulesets: dict[str, RuleSet] = {}
    for path in sorted(base.glob("*.json")):
        if path.name == "whitelist.json":
            continue
        ruleset = _load_ruleset(path)
        if ruleset.analyzer in rulesets:
            raise RuleLoadError(str(path), f"duplicate analyzer {ruleset.analyzer!r}")
        rulesets[ruleset.analyzer] = ruleset
    return rulesets


def _rule_index(rulesets: dict[str, RuleSet] | None = None) -> dict[str, Rule]:
    """Build a flat rule_id -> Rule index across all documents."""
    catalog = rulesets if rulesets is not None else _load_all()
    index: dict[str, Rule] = {}
    for ruleset in catalog.values():
        for rule in ruleset.rules:
            if rule.rule_id in index:
                raise RuleLoadError(
                    ruleset.analyzer, f"rule_id {rule.rule_id!r} defined in multiple documents"
                )
            index[rule.rule_id] = rule
    return index


def _find_rule(rule_id: str, rulesets: dict[str, RuleSet] | None = None) -> Rule | None:
    """Look up a rule by identifier across all rule documents."""
    return _rule_index(rulesets).get(rule_id)


def _rules_for(analyzer: str, enabled_only: bool = True) -> list[Rule]:
    """Return the rules for one analyzer, optionally only enabled ones."""
    ruleset = _load_rules(analyzer)
    return ruleset._enabled_rules() if enabled_only else list(ruleset.rules)


def _validate_all(directory: Path | None = None) -> list[str]:
    """Validate every rule document and return human readable summaries."""
    summaries: list[str] = []
    for analyzer, ruleset in _load_all(directory).items():
        enabled = len(ruleset._enabled_rules())
        summaries.append(
            f"{analyzer}: {len(ruleset.rules)} rules ({enabled} enabled) "
            f"v{ruleset.schema_version}"
        )
    return summaries


def _to_dict(rule: Rule) -> dict[str, Any]:
    """Serialize a rule to a JSON-safe dictionary for reporters."""
    data = rule.model_dump(mode="json")
    data["severity"] = rule.severity.value
    return data


def _domain_matches(host: str, patterns: Iterable[str]) -> bool:
    """Return True if host matches any exact or wildcard domain pattern."""
    h = host.lower().strip()
    if ":" in h:
        h = h.split(":", 1)[0]
    for pattern in patterns:
        p = pattern.lower().strip()
        if not p:
            continue
        if p.startswith("*."):
            base = p[2:]
            if h == base or h.endswith("." + base):
                return True
        elif p.startswith("."):
            base = p[1:]
            if h == base or h.endswith("." + base):
                return True
        else:
            if h == p:
                return True
    return False


def _load_whitelist() -> dict[str, list[str]]:
    """Load default whitelist configuration and optional local .sentinelwhitelist."""
    whitelist_path = RULE_DIRECTORY / "whitelist.json"
    domains: list[str] = ["localhost", "127.0.0.1"]
    trusted_external: list[str] = []

    if whitelist_path.is_file():
        try:
            raw = whitelist_path.read_text(encoding="utf-8")
            data = json.loads(raw)
            if isinstance(data, dict):
                domains = [str(d) for d in data.get("domains", domains)]
                trusted_external = [str(d) for d in data.get("trusted_external_links", [])]
        except (OSError, json.JSONDecodeError):
            pass

    # Load local .sentinelwhitelist in current working directory if present
    local_whitelist = Path.cwd() / ".sentinelwhitelist"
    if local_whitelist.is_file():
        try:
            content = local_whitelist.read_text(encoding="utf-8", errors="replace")
            for line in content.splitlines():
                stripped = line.partition("#")[0].strip()
                if stripped and stripped not in domains:
                    domains.append(stripped)
        except OSError:
            pass

    return {
        "domains": domains,
        "trusted_external_links": trusted_external,
    }
