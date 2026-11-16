from __future__ import annotations
import math, re
from pathlib import Path
from typing import Any

class SecretAuditor:
    def _entropy(self, text: str) -> float:
        if not text:
            return 0.0
        prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(text)]
        return -sum(p * math.log2(p) for p in prob)

    def _signatures(self) -> list[tuple[str, str, str, str]]:
        return [
            ("SEC010", "CRITICAL", r"\bAKIA[0-9A-Z]{16}\b", "AWS Access Key ID"),
            (
                "SEC011",
                "CRITICAL",
                r"-----BEGIN (?:RSA|EC|OPENSSH|DSA|PGP) PRIVATE KEY-----",
                "Private Key Block",
            ),
            (
                "SEC012",
                "CRITICAL",
                r"\b(?:ghp|gho|ghu|ghs|ghr)_[0-9a-zA-Z]{36}\b",
                "GitHub Personal Token",
            ),
            ("SEC013", "CRITICAL", r"\bgithub_pat_[0-9a-zA-Z_]{82}\b", "GitHub Fine-Grained Token"),
            ("SEC014", "CRITICAL", r"\bsk-(?:proj-)?[a-zA-Z0-9_-]{40,}\b", "OpenAI API Secret Key"),
            ("SEC015", "CRITICAL", r"\bsk-ant-[a-zA-Z0-9_\-]{80,}\b", "Anthropic API Key"),
            ("SEC016", "CRITICAL", r"\bhf_[a-zA-Z0-9]{34}\b", "HuggingFace Access Token"),
            ("SEC017", "CRITICAL", r"\bsk_live_[0-9a-zA-Z]{24,}\b", "Stripe Live Secret Key"),
            (
                "SEC018",
                "CRITICAL",
                r"\bSG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}\b",
                "SendGrid API Key",
            ),
            ("SEC019", "CRITICAL", r"\bSK[0-9a-fA-F]{32}\b", "Twilio API Key"),
            ("SEC020", "HIGH", r"\bxox[baprs]-[0-9a-zA-Z]{10,48}\b", "Slack Token"),
            ("SEC021", "HIGH", r"\bAIza[0-9A-Za-z\-_]{35}\b", "Google Cloud API Key"),
            (
                "SEC022",
                "HIGH",
                r"""(?:postgres|mysql|mongodb(?:\+srv)?|redis):\/\/[a-zA-Z0-9_]+:[^@\s"']+@[a-zA-Z0-9_\-\.]+""",
                "Database Connection String with Credentials",
            ),
            (
                "SEC023",
                "HIGH",
                r"""(?i)(?:api[_-]?key|secret[_-]?key|auth[_-]?token)\s*[:=]\s*['"][a-zA-Z0-9_\-]{24,}['"]""",
                "High-Entropy Generic API Credential",
            ),
        ]

    def _audit_content(self, content: str, file_path: str) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        lines = content.splitlines()

        for rule_id, sev, pat, title in self._signatures():
            for idx, line in enumerate(lines, 1):
                m = re.search(pat, line)
                if m:
                    snippet = line.strip()
                    if len(snippet) > 75:
                        snippet = snippet[:72] + "..."
                    findings.append(
                        {
                            "rule_id": rule_id,
                            "severity": sev,
                            "title": title,
                            "file": file_path,
                            "line": idx,
                            "snippet": snippet,
                            "remediation": "Revoke leaked credential immediately and use vault.",
                        }
                    )

        entropy_kw = ("token", "secret", "password", "api_key", "apikey", "private_key")
        for idx, line in enumerate(lines, 1):
            if any(k in line.lower() for k in entropy_kw):
                matches = re.findall(r"['\"]([a-zA-Z0-9_\-\/+=]{32,})['\"]", line)
                for val in matches:
                    if self._entropy(val) > 4.2 and not any(f["line"] == idx for f in findings):
                        snippet = line.strip()
                        if len(snippet) > 75:
                            snippet = snippet[:72] + "..."
                        findings.append(
                            {
                                "rule_id": "SEC030",
                                "severity": "HIGH",
                                "title": "High-Entropy Suspicious Token / Secret",
                                "file": file_path,
                                "line": idx,
                                "snippet": snippet,
                                "remediation": "Verify if string is secret material; move to env.",
                            }
                        )
                        break

        return findings

    def _scan_target(self, target: str | Path) -> tuple[int, list[dict[str, Any]]]:
        p = Path(target).resolve()
        if p.is_file():
            try:
                content = p.read_text(encoding="utf-8", errors="ignore")
                res = self._audit_content(content, str(p).replace("\\", "/"))
                return len(res), res
            except Exception:
                return 0, []

        all_findings: list[dict[str, Any]] = []
        ignored = {
            ".git", ".venv", "venv", "node_modules", "__pycache__",
            "package-lock.json", "yarn.lock", "poetry.lock",
        }
        binary_ext = {
            ".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip",
            ".tar", ".gz", ".exe", ".bin", ".pyc", ".woff", ".woff2",
        }

        for item in sorted(p.rglob("*")):
            if any(part in ignored for part in item.parts):
                continue
            if item.is_file() and item.suffix.lower() not in binary_ext:
                try:
                    content = item.read_text(encoding="utf-8", errors="ignore")
                    rel = str(item).replace("\\", "/")
                    all_findings.extend(self._audit_content(content, rel))
                except Exception:
                    continue

        return len(all_findings), all_findings

    def _render_text(self, findings: list[dict[str, Any]], target: str) -> str:
        if not findings:
            return (
                f"Sentinel Secrets: No hardcoded credentials or leaks detected in {target}."
            )

        lines: list[str] = [
            f"Sentinel Secrets: Found {len(findings)} leaked credential(s) in {target}:\n"
        ]
        for f in findings:
            lines.append(f"[{f['severity']}] {f['rule_id']} - {f['title']}")
            lines.append(f"  • File: {f['file']}:{f['line']}")
            lines.append(f"  • Snippet: {f['snippet']}")
            lines.append(f"  • Remediation: {f['remediation']}\n")
        return "\n".join(lines)

_scanner = SecretAuditor()

def _scan(target: str | Path) -> tuple[int, list[dict[str, Any]]]:
    return _scanner._scan_target(target)

def _render(findings: list[dict[str, Any]], target: str) -> str:
    return _scanner._render_text(findings, target)
