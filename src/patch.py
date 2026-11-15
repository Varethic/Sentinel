from __future__ import annotations
import difflib, re
from pathlib import Path

class Patcher:
    def _patterns(self) -> list[tuple[str, str, str, str]]:
        return [
            (
                "CMDI002",
                r"\bshell\s*=\s*True\b",
                "shell=False",
                "Disabled shell=True in subprocess call",
            ),
            (
                "AUTH001",
                r"\bverify\s*=\s*False\b",
                "verify=True",
                "Enforced TLS certificate verification (verify=True)",
            ),
            (
                "AUTH003",
                r"\bdebug\s*=\s*True\b",
                "debug=False",
                "Disabled debug mode in web application",
            ),
            (
                "XSS003",
                r"\bautoescape\s*=\s*False\b",
                "autoescape=True",
                "Enabled automatic template escaping",
            ),
            (
                "API001",
                r"\bintrospection\s*=\s*True\b",
                "introspection=False",
                "Disabled GraphQL schema introspection",
            ),
            (
                "SECR003",
                r"\brandom\.choice\b",
                "secrets.choice",
                "Replaced weak pseudo-random choice with secrets.choice",
            ),
            (
                "SECR003",
                r"\brandom\.randint\b",
                "secrets.randbelow",
                "Replaced weak pseudo-random randint with secrets.randbelow",
            ),
            (
                "SECR003",
                r"\bimport\s+random\b",
                "import secrets",
                "Replaced insecure random import with secrets module",
            ),
        ]

    def _diff(self, file_path: str, original: str, patched: str) -> str:
        orig_lines = original.splitlines(keepends=True)
        patch_lines = patched.splitlines(keepends=True)
        rel_path = file_path.replace("\\", "/")
        diff = difflib.unified_diff(
            orig_lines,
            patch_lines,
            fromfile=f"a/{rel_path}",
            tofile=f"b/{rel_path}",
        )
        return "".join(diff)

    def _patch_code(
        self,
        source: str,
        file_path: str,
        rules: set[str] | None = None,
    ) -> tuple[str, list[str]]:
        current = source
        applied: list[str] = []
        for rule_id, pattern, replacement, desc in self._patterns():
            if rules and rule_id not in rules:
                continue
            matches = list(re.finditer(pattern, current))
            if matches:
                current = re.sub(pattern, replacement, current)
                plural = "s" if len(matches) > 1 else ""
                applied.append(f"{rule_id}: {desc} ({len(matches)} occurrence{plural})")
        return current, applied

    def _fix_file(
        self,
        file_path: str | Path,
        write: bool = False,
        rules: set[str] | None = None,
    ) -> tuple[int, str, list[str]]:
        p = Path(file_path).resolve()
        if not p.is_file():
            return 0, "", []
        try:
            original = p.read_text(encoding="utf-8")
        except Exception:
            return 0, "", []

        patched, applied = self._patch_code(original, str(p), rules)
        if original == patched:
            return 0, "", []

        diff = self._diff(str(p), original, patched)
        if write:
            p.write_text(patched, encoding="utf-8")
        return len(applied), diff, applied

    def _fix_target(
        self,
        target: str | Path,
        write: bool = False,
        rules: set[str] | None = None,
    ) -> tuple[int, str, list[str]]:
        p = Path(target).resolve()
        total_fixes = 0
        diff_chunks: list[str] = []
        all_applied: list[str] = []

        if p.is_file():
            fixes, diff, app = self._fix_file(p, write=write, rules=rules)
            if fixes:
                total_fixes += fixes
                diff_chunks.append(diff)
                all_applied.extend(app)
            return total_fixes, "\n".join(diff_chunks), all_applied

        ignored_dirs = {".git", ".venv", "venv", "node_modules", "__pycache__"}
        for file_p in sorted(p.rglob("*")):
            if any(part in ignored_dirs for part in file_p.parts):
                continue
            if file_p.is_file() and file_p.suffix in (".py", ".pyi", ".js", ".ts", ".php", ".html"):
                fixes, diff, app = self._fix_file(file_p, write=write, rules=rules)
                if fixes:
                    total_fixes += fixes
                    diff_chunks.append(diff)
                    all_applied.extend(app)

        return total_fixes, "\n".join(diff_chunks), all_applied

_patcher = Patcher()

def _fix(
    target: str | Path,
    write: bool = False,
    rules: set[str] | None = None,
) -> tuple[int, str, list[str]]:
    return _patcher._fix_target(target, write=write, rules=rules)
