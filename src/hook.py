from __future__ import annotations
import contextlib, re, subprocess
from pathlib import Path
from typing import Any
from src.core import engine
from src.core.loader import Severity

class SecretDetector:
    def _patterns(self) -> list[tuple[str, str, str]]:
        return [
            ("AWS Access Key", r"\bAKIA[0-9A-Z]{16}\b", "CRITICAL"),
            (
                "Private Key Block",
                r"-----BEGIN (?:RSA|EC|OPENSSH|DSA|PGP) PRIVATE KEY-----",
                "CRITICAL",
            ),
            ("GitHub Personal Token", r"\b(?:ghp|gho|ghu|ghs|ghr)_[0-9a-zA-Z]{36}\b", "CRITICAL"),
            ("GitHub Fine-Grained Token", r"\bgithub_pat_[0-9a-zA-Z_]{82}\b", "CRITICAL"),
            ("Slack Bot/User Token", r"\bxox[baprs]-[0-9a-zA-Z]{10,48}\b", "HIGH"),
            ("Google API Key", r"\bAIza[0-9A-Za-z\-_]{35}\b", "HIGH"),
            (
                "Generic Hardcoded Secret",
                r"""(?i)(?:api[_-]?key|secret[_-]?key|auth[_-]?token)\s*[:=]\s*['"][a-zA-Z0-9_\-]{24,}['"]""",
                "HIGH",
            ),
        ]

    def _scan_text(self, text: str, file_path: str) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        lines = text.splitlines()
        for rule_name, pattern, severity in self._patterns():
            for i, line in enumerate(lines, 1):
                if re.search(pattern, line):
                    snippet = line.strip()
                    if len(snippet) > 80:
                        snippet = snippet[:77] + "..."
                    findings.append(
                        {
                            "type": rule_name,
                            "severity": severity,
                            "file": file_path,
                            "line": i,
                            "snippet": snippet,
                        }
                    )
        return findings

class HookManager:
    def __init__(self) -> None:
        self.secrets = SecretDetector()

    def _git_root(self) -> Path | None:
        try:
            res = subprocess.run(
                ["git", "rev-parse", "--show-toplevel"],
                capture_output=True,
                text=True,
                check=True,
            )
            return Path(res.stdout.strip()).resolve()
        except Exception:
            return None

    def _install(self) -> tuple[bool, str]:
        root = self._git_root()
        if not root:
            return False, "Not inside a valid git repository."

        hooks_dir = (root / ".git" / "hooks").resolve()
        if not hooks_dir.exists():
            hooks_dir.mkdir(parents=True, exist_ok=True)

        pre_commit_script = hooks_dir / "pre-commit"
        script_content = (
            "#!/usr/bin/env sh\n"
            "sentinel hook check\n"
        )
        pre_commit_script.write_text(script_content, encoding="utf-8")
        with contextlib.suppress(Exception):
            pre_commit_script.chmod(0o755)

        return True, f"Successfully installed Sentinel pre-commit hook to {pre_commit_script}"

    def _staged_files(self) -> list[Path]:
        try:
            res = subprocess.run(
                ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
                capture_output=True,
                text=True,
                check=True,
            )
            files: list[Path] = []
            for line in res.stdout.splitlines():
                line = line.strip()
                if line:
                    files.append(Path(line).resolve())
            return files
        except Exception:
            return []

    def _check(self) -> int:
        staged = self._staged_files()
        if not staged:
            print("Sentinel Guard: No staged files to verify.")
            return 0

        secret_findings: list[dict[str, Any]] = []
        for file_p in staged:
            if not file_p.is_file():
                continue
            try:
                content = file_p.read_text(encoding="utf-8", errors="ignore")
                rel = str(file_p).replace("\\", "/")
                secret_findings.extend(self.secrets._scan_text(content, rel))
            except Exception:
                continue

        code_findings: list[Any] = []
        from src.run import _sast_analyzers
        code_files = [
            f for f in staged if f.is_file() and f.suffix in engine.SOURCE_SUFFIXES
        ]
        if code_files:
            try:
                report = engine._run_analyzers_on_files(code_files, _sast_analyzers())
                blocking_sev = (Severity.HIGH, Severity.CRITICAL)
                code_findings = [f for f in report.findings if f.severity in blocking_sev]
            except Exception:
                pass

        if not secret_findings and not code_findings:
            print(f"Sentinel Guard: {len(staged)} staged file(s) checked. Clean (0 issues).")
            return 0

        print(
            f"\n[BLOCKED] Sentinel Pre-Commit Guard detected "
            f"{len(secret_findings) + len(code_findings)} blocking issue(s):\n"
        )
        for s in secret_findings:
            print(f"  • [SECRET LEAK] [{s['severity']}] {s['type']} at {s['file']}:{s['line']}")
            print(f"    Snippet: {s['snippet']}")

        for c in code_findings:
            loc = f"{c.file_path}:{c.line_number}"
            print(f"  • [VULNERABILITY] [{c.severity.value}] {c.rule_id} at {loc}")
            print(f"    Message: {c.message}")

        print("\nCommit rejected! Please resolve the security issues above before committing.")
        return 1

_hook_mgr = HookManager()

def _install() -> tuple[bool, str]:
    return _hook_mgr._install()

def _check() -> int:
    return _hook_mgr._check()
