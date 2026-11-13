"""Core analysis engine: Finding model, AST plumbing and file traversal.

This module deliberately contains no detection logic. Analyzers register
themselves as AST visitors here so that traversal, de-duplication, sorting and
rendering stay in one place.
"""

from __future__ import annotations

import ast
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Protocol

from pydantic import BaseModel, ConfigDict, Field

from src.core.loader import Rule, Severity, _rules_for

SNIPPET_LIMIT: int = 160
DEFAULT_EXCLUDED: frozenset[str] = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".venv",
        "venv",
        "env",
        "node_modules",
        "__pycache__",
        "build",
        "dist",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        "site-packages",
        ".tox",
        ".idea",
        ".vscode",
    }
)

SOURCE_SUFFIXES: frozenset[str] = frozenset({".py", ".pyi"})


class Finding(BaseModel):
    """A single, fully attributed security finding."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    rule_id: str = Field(..., min_length=3)
    rule_name: str = Field(..., min_length=3)
    severity: Severity
    category: str = Field(default="", min_length=0)
    cwe_id: str = Field(default="", min_length=0)
    cve: str = Field(default="", min_length=0)
    cve_date: str = Field(default="", min_length=0)
    file_path: str = Field(..., min_length=1)
    line_number: int = Field(..., ge=0)
    column: int = Field(default=0, ge=0)
    code_snippet: str = Field(default="")
    message: str = Field(..., min_length=1)
    remediation: str = Field(default="")

    def _is_blocking(self) -> bool:
        """Return True when this finding should fail a CI pipeline."""
        return self.severity in (Severity.HIGH, Severity.CRITICAL)

    def _sort_key(self) -> tuple[int, str, int, str]:
        """Order findings by severity (highest first), then by location."""
        return (
            -self.severity._rank(),
            self.file_path,
            self.line_number,
            self.rule_id,
        )

    def _identity(self) -> tuple[str, str, int, str]:
        """Deduplication key for identical detections."""
        return (self.rule_id, self.file_path, self.line_number, self.message)

    def _location(self) -> str:
        """Render a compact 'file:line' location string."""
        return f"{self.file_path}:{self.line_number}"

    def _cve_label(self) -> str:
        """Render the reference CVE and its publication date, if known."""
        if not self.cve:
            return ""
        if self.cve_date:
            return f"{self.cve} ({self.cve_date})"
        return self.cve


@dataclass(frozen=True)
class SourceFile:
    """A parsed Python source file ready for analysis."""

    path: Path
    display_path: str
    source: str
    tree: ast.AST
    lines: tuple[str, ...] = field(default=())


@dataclass(frozen=True)
class AnalysisResult:
    """Aggregated output of one analyzer run over a set of files."""

    findings: tuple[Finding, ...]
    files_scanned: int
    files_skipped: int
    errors: tuple[str, ...] = field(default=())

    def _blocking(self) -> tuple[Finding, ...]:
        """Return only findings that should fail the build."""
        return tuple(item for item in self.findings if item._is_blocking())

    def _counts(self) -> dict[str, int]:
        """Count findings per severity label."""
        counts = {level.value: 0 for level in Severity}
        for item in self.findings:
            counts[item.severity.value] += 1
        return counts

    def _has_blocking(self) -> bool:
        """Return True when at least one HIGH/CRITICAL finding exists."""
        return any(item._is_blocking() for item in self.findings)


class Analyzer(Protocol):
    """Protocol implemented by every AST analyzer module."""

    def _name(self) -> str:
        """Short analyzer identifier matching the JSON document name."""
        ...

    def _analyze(self, target: SourceFile) -> list[Finding]:
        """Inspect one parsed source file and return raw findings."""
        ...


class Visitor(ast.NodeVisitor):
    """Base AST visitor that records findings against a source file.

    Subclasses implement ``visit_*`` handlers (the only names exempt from the
    leading-underscore convention) and call ``_add`` to record a violation.
    """

    def __init__(self, target: SourceFile, rules: Sequence[Rule]) -> None:
        """Store the file under analysis plus its applicable rules."""
        self._target = target
        self._rules = list(rules)
        self._rulemap = {rule.rule_id: rule for rule in self._rules}
        self.findings: list[Finding] = []

    def _rule(self, rule_id: str) -> Rule | None:
        """Return the active rule for an identifier, or None if disabled."""
        return self._rulemap.get(rule_id)

    def _snippet(self, node: ast.AST) -> str:
        """Extract the source line for a node, trimmed for display."""
        lineno = getattr(node, "lineno", 0) or 0
        if not lineno or lineno > len(self._target.lines):
            return ""
        text = self._target.lines[lineno - 1].strip()
        if len(text) > SNIPPET_LIMIT:
            text = text[: SNIPPET_LIMIT - 3].rstrip() + "..."
        return text

    def _add(self, rule_id: str, node: ast.AST, message: str) -> None:
        """Record a finding for ``rule_id`` at the node's position."""
        rule = self._rule(rule_id)
        if rule is None:
            return
        self.findings.append(
            Finding(
                rule_id=rule.rule_id,
                rule_name=rule.name,
                severity=rule.severity,
                category=rule.category,
                cwe_id=rule.cwe_id,
                cve=rule.cve,
                cve_date=rule.cve_date,
                file_path=self._target.display_path,
                line_number=getattr(node, "lineno", 0) or 0,
                column=getattr(node, "col_offset", 0) or 0,
                code_snippet=self._snippet(node),
                message=message,
                remediation=rule.remediation_example,
            )
        )

    def _run(self) -> list[Finding]:
        """Visit the parsed tree and return findings."""
        self.visit(self._target.tree)
        return self.findings


class DynamicKind(str, Enum):
    """Categories of dynamic string construction detected in an expression."""

    FSTRING = "fstring"
    CONCAT = "concat"
    PERCENT = "percent"
    FORMAT = "format"
    TEMPLATE = "template"
    NAME = "name"
    NONE = "none"


def _call_name(node: ast.AST) -> str:
    """Return the lowercase final name of a call target (func or method)."""
    if isinstance(node, ast.Call):
        return _call_name(node.func)
    if isinstance(node, ast.Attribute):
        return node.attr.lower()
    if isinstance(node, ast.Name):
        return node.id.lower()
    return ""


def _dotted_name(node: ast.AST) -> str:
    """Render a dotted name for an expression, e.g. 'flask.render_template'."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _dotted_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    if isinstance(node, ast.Call):
        return _dotted_name(node.func)
    return ""


def _string_value(node: ast.AST) -> str | None:
    """Return the literal string value of a constant node, else None."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _iter_subexpressions(node: ast.AST) -> Iterator[ast.AST]:
    """Yield the node and all of its descendants (including itself)."""
    yield node
    for child in ast.iter_child_nodes(node):
        yield from _iter_subexpressions(child)


def _dynamic_kind(node: ast.AST) -> DynamicKind:
    """Classify how a single expression builds its string."""
    if isinstance(node, ast.JoinedStr):
        return DynamicKind.FSTRING
    if isinstance(node, ast.BinOp):
        if isinstance(node.op, ast.Add):
            return DynamicKind.CONCAT
        if isinstance(node.op, ast.Mod):
            return DynamicKind.PERCENT
    if isinstance(node, ast.Call):
        name = _call_name(node)
        if name == "format":
            return DynamicKind.FORMAT
        if name in {"substitute", "safe_substitute"}:
            return DynamicKind.TEMPLATE
    if isinstance(node, (ast.Name, ast.Attribute, ast.Subscript)):
        return DynamicKind.NAME
    return DynamicKind.NONE


def _contains_dynamic(node: ast.AST, kinds: Iterable[str]) -> bool:
    """Return True when any subexpression matches one of the requested kinds."""
    wanted = {kind.lower() for kind in kinds}
    if not wanted:
        wanted = {
            DynamicKind.FSTRING.value,
            DynamicKind.CONCAT.value,
            DynamicKind.PERCENT.value,
            DynamicKind.FORMAT.value,
            DynamicKind.TEMPLATE.value,
        }
    for child in _iter_subexpressions(node):
        if isinstance(child, ast.JoinedStr) and DynamicKind.FSTRING.value in wanted:
            return True
        if isinstance(child, ast.BinOp):
            if isinstance(child.op, ast.Add) and DynamicKind.CONCAT.value in wanted:
                return True
            if isinstance(child.op, ast.Mod) and DynamicKind.PERCENT.value in wanted:
                return True
        if isinstance(child, ast.Call):
            name = _call_name(child)
            if name == "format" and DynamicKind.FORMAT.value in wanted:
                return True
            if name in {"substitute", "safe_substitute"} and DynamicKind.TEMPLATE.value in wanted:
                return True
        if (
            isinstance(child, (ast.Name, ast.Attribute, ast.Subscript))
            and DynamicKind.NAME.value in wanted
        ):
            return True
    return False


def _mentions_sql(node: ast.AST, keywords: Sequence[str]) -> bool:
    """Return True when a literal/name in the expression looks like SQL."""
    lowered = [keyword.lower() for keyword in keywords]
    for child in _iter_subexpressions(node):
        text = _string_value(child)
        if text is None:
            continue
        probe = text.lower()
        if any(keyword in probe for keyword in lowered):
            return True
    return False


def _import_aliases(tree: ast.AST) -> dict[str, str]:
    """Map local import aliases to the dotted module they refer to.

    ``import xml.etree.ElementTree as ET`` maps ``ET`` -> ``xml.etree.
    elementtree``, ``from xml.dom import minidom`` maps ``minidom`` ->
    ``xml.dom.minidom``, and ``from jinja2 import Template as JTemplate`` maps
    ``jtemplate`` -> ``jinja2.template``. Without this, aliased sinks in any
    analyzer are invisible because only the local name appears in the AST.

    Keys and values are lowercased so callers can compare case-insensitively.
    """
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                local = alias.asname or alias.name.split(".")[0]
                aliases[local.lower()] = alias.name.lower()
        elif isinstance(node, ast.ImportFrom):
            if not node.module:
                continue
            base = node.module.lower()
            for alias in node.names:
                local = alias.asname or alias.name
                aliases[local.lower()] = f"{base}.{alias.name.lower()}"
    return aliases


def _resolve_dotted(dotted: str, aliases: dict[str, str]) -> str:
    """Expand a dotted name's leading alias into its full module path.

    ``_resolve_dotted('ET.parse', {'et': 'xml.etree.elementtree'})`` returns
    ``xml.etree.elementtree.parse``, so module matching works on the real path
    rather than the operator's chosen local name.
    """
    if not dotted:
        return ""
    parts = dotted.split(".")
    head = parts[0].lower()
    resolved = aliases.get(head)
    if resolved is None:
        return dotted.lower()
    remainder = parts[1:]
    return ".".join([resolved, *(part.lower() for part in remainder)])


def _normalize_name(text: str | None) -> str:
    """Lowercase a name and strip look-alike separators for matching.

    ``ALLOWED_HOSTS``, ``allowed-hosts`` and ``allowedHosts`` all normalize to
    ``allowedhosts``, so guard detection is insensitive to naming style.
    """
    if not text:
        return ""
    return text.lower().replace("-", "").replace("_", "")


def _enclosing_scope(tree: ast.AST, node: ast.AST) -> ast.AST:
    """Return the innermost function/class body containing ``node``.

    Used to keep guard analysis per-function: a value validated in one function
    must not be treated as validated in an unrelated one.
    """
    found: ast.AST = tree
    lineno = getattr(node, "lineno", 0)
    for candidate in ast.walk(tree):
        if candidate is node or not hasattr(candidate, "body"):
            continue
        if not isinstance(candidate, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        start = getattr(candidate, "lineno", 0)
        end = getattr(candidate, "end_lineno", start)
        if start <= lineno <= end:
            found = candidate
    return found


def _call_arguments(node: ast.Call) -> list[ast.AST]:
    """Return every positional and keyword value passed to a call."""
    values = list(node.args)
    values.extend(keyword.value for keyword in node.keywords)
    return values


def _looks_like_allowlist(node: ast.AST) -> bool:
    """Return True when a comparator name reads like an allow-list."""
    name = _normalize_name(_dotted_name(node))
    return any(token in name for token in ("allow", "white", "safe", "trust", "valid"))


def _guarded_names(
    tree: ast.AST,
    node: ast.AST,
    guard_calls: Iterable[str] = (),
    guard_tokens: Iterable[str] = (),
) -> set[str]:
    """Return names validated by an allow-list guard in the enclosing scope.

    Recognizes the defensive shapes that appear in real code:

    * ``if host not in ALLOWED_HOSTS: raise ...`` - the left operand of a
      membership test against an allow-list-looking name;
    * ``if not is_allowed_host(host): raise ...`` - the argument of a guard call
      named in ``guard_calls``;
    * ``if not is_safe(url)`` - a guard call whose name contains one of
      ``guard_tokens``.

    Names are also extended to the values they were derived from, so
    ``host = urlparse(url).hostname`` followed by a guard on ``host`` validates
    ``url`` as well.
    """
    guarded: set[str] = set()
    call_names = {_normalize_name(item) for item in guard_calls}
    tokens = {_normalize_name(item) for item in guard_tokens}
    scope = _enclosing_scope(tree, node)

    for child in ast.walk(scope):
        if not isinstance(child, ast.If):
            continue
        for test in ast.walk(child.test):
            if isinstance(test, ast.Compare):
                for op, comparator in zip(test.ops, test.comparators):
                    if not isinstance(op, (ast.In, ast.NotIn)):
                        continue
                    if not isinstance(test.left, ast.Name):
                        continue
                    if _looks_like_allowlist(comparator):
                        guarded.add(_normalize_name(test.left.id))
            elif isinstance(test, ast.Call):
                name = _normalize_name(_dotted_name(test.func).rsplit(".", 1)[-1])
                if name in call_names or any(token and token in name for token in tokens):
                    for argument in _call_arguments(test):
                        if isinstance(argument, ast.Name):
                            guarded.add(_normalize_name(argument.id))
    return _validated_sources(scope, guarded)


def _validated_sources(scope: ast.AST, guarded: set[str]) -> set[str]:
    """Extend validated names to the inputs a derivation reads from.

    A guard that checks ``host = urlparse(url).hostname`` validates ``url`` too:
    the value under test was derived from it, so ``url`` is genuinely constrained.
    """
    validated = set(guarded)
    changed = True
    while changed:
        changed = False
        for node in ast.walk(scope):
            if not isinstance(node, (ast.Assign, ast.AnnAssign)):
                continue
            value = node.value
            if value is None:
                continue
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            names = {_normalize_name(t.id) for t in targets if isinstance(t, ast.Name)}
            if not names or not (names & validated):
                continue
            for child in _iter_subexpressions(value):
                if isinstance(child, ast.Name):
                    normalized = _normalize_name(child.id)
                    if normalized not in validated:
                        validated.add(normalized)
                        changed = True
    return validated


def _uses_only_guarded_names(node: ast.AST, guarded: set[str]) -> bool:
    """Return True when an expression only reads allow-list validated names.

    An expression with no bare names (a literal, or a chain of call results)
    returns False so the caller keeps reporting it.
    """
    if not guarded:
        return False
    names = {
        _normalize_name(child.id)
        for child in _iter_subexpressions(node)
        if isinstance(child, ast.Name)
    }
    if not names:
        return False
    return names.issubset(guarded)


def _mentions_guard(node: ast.AST, tokens: Iterable[str] = ()) -> bool:
    """Return True when an expression passes through an obvious guard.

    Matches a call whose name contains one of ``tokens`` (for example
    ``is_safe_url(...)``) or a bare reference to such a name.
    """
    wanted = {_normalize_name(token) for token in tokens}
    if not wanted:
        return False
    for child in _iter_subexpressions(node):
        if isinstance(child, ast.Call):
            name = _normalize_name(_call_name(child))
            if any(token and token in name for token in wanted):
                return True
        elif isinstance(child, ast.Name):
            if _normalize_name(child.id) in wanted:
                return True
    return False


def _matches_module(dotted: str, modules: Iterable[str]) -> str:
    """Return the longest configured module prefix of a dotted name, or ''.

    ``xml.etree.ElementTree.parse`` matches ``xml.etree`` and ``elementtree``,
    returning the longest configured prefix so callers can name the provider.
    """
    lowered = (dotted or "").lower()
    if not lowered:
        return ""
    known = {module.lower() for module in modules if module}
    parts = lowered.split(".")
    for index in range(len(parts) - 1, 0, -1):
        candidate = ".".join(parts[:index])
        if candidate in known:
            return candidate
    return ""


def _collect_files(
    target: Path,
    excluded: frozenset[str] = DEFAULT_EXCLUDED,
    suffixes: frozenset[str] = SOURCE_SUFFIXES,
) -> tuple[list[Path], int]:
    """Collect analyzable source files under a file or directory target."""
    resolved = target.expanduser().resolve()
    if not resolved.exists():
        raise FileNotFoundError(f"target not found: {target}")

    if resolved.is_file():
        if resolved.suffix.lower() not in suffixes:
            raise ValueError(f"unsupported file type: {resolved.suffix or '(none)'}")
        return [resolved], 0

    files: list[Path] = []
    skipped = 0
    for path in sorted(resolved.rglob("*")):
        if any(part in excluded for part in path.parts):
            continue
        if not path.is_file():
            continue
        if path.suffix.lower() in suffixes:
            files.append(path)
        else:
            skipped += 1
    return files, skipped


def _display_path(path: Path, root: Path) -> str:
    """Return the path as written by the operator, relative to the scan root."""
    resolved = path.resolve()

    if root.is_file():
        # Single-file scan: prefer an operator-friendly relative path.
        for base in (Path.cwd().resolve(), root.parent.resolve()):
            try:
                return str(resolved.relative_to(base))
            except ValueError:
                continue
        return str(resolved)

    try:
        return str(resolved.relative_to(root.resolve()))
    except ValueError:
        return str(resolved)


def _parse_ast(path: Path, source: str) -> ast.AST:
    """Parse source text into an AST, decoded from bytes like CPython does."""
    data = path.read_bytes()
    return ast.parse(data, filename=str(path))


def _read_source(path: Path, root: Path) -> SourceFile:
    """Read, decode and parse a single Python file."""
    raw = path.read_bytes()
    source = raw.decode("utf-8-sig", errors="replace")
    tree = _parse_ast(path, source)
    return SourceFile(
        path=path,
        display_path=_display_path(path, root),
        source=source,
        tree=tree,
        lines=tuple(source.splitlines()),
    )


def _dedupe(findings: Iterable[Finding]) -> list[Finding]:
    """Remove duplicate findings and sort by severity then location."""
    seen: set[tuple[str, str, int, str]] = set()
    unique: list[Finding] = []
    for item in findings:
        key = item._identity()
        if key in seen:
            continue
        seen.add(key)
        unique.append(item)
    unique.sort(key=Finding._sort_key)
    return unique


def _run_analyzers(
    target: Path,
    analyzers: Sequence[Analyzer],
    excluded: frozenset[str] = DEFAULT_EXCLUDED,
) -> AnalysisResult:
    """Run every analyzer over a file or directory target."""
    root = target.expanduser()
    files, skipped = _collect_files(root, excluded=excluded)

    rules_by_analyzer = {
        analyzer._name(): _rules_for(analyzer._name()) for analyzer in analyzers
    }

    findings: list[Finding] = []
    errors: list[str] = []
    scanned = 0

    for path in files:
        try:
            source_file = _read_source(path, root)
        except (OSError, SyntaxError, ValueError) as exc:
            errors.append(f"{_display_path(path, root)}: {exc.__class__.__name__}: {exc}")
            continue
        scanned += 1
        for analyzer in analyzers:
            name = analyzer._name()
            rules = rules_by_analyzer.get(name) or []
            if not rules:
                continue
            try:
                findings.extend(analyzer._analyze(source_file))
            except (SyntaxError, ValueError, RecursionError) as exc:
                errors.append(f"{source_file.display_path}: analyzer {name} failed: {exc}")

    return AnalysisResult(
        findings=tuple(_dedupe(findings)),
        files_scanned=scanned,
        files_skipped=skipped,
        errors=tuple(errors),
    )
