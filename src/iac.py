from __future__ import annotations
import re
from pathlib import Path
from typing import Any

class IacAuditor:
    def _patterns_dockerfile(self) -> list[tuple[str, str, str, str, str]]:
        return [
            (
                "IAC001",
                "CRITICAL",
                r"^\s*USER\s+(?:root|0)\s*$",
                "Container runs as root user (USER root)",
                "Specify a non-privileged user (e.g. USER appuser or USER 10001).",
            ),
            (
                "IAC002",
                "HIGH",
                r"^\s*FROM\s+([a-zA-Z0-9_\-\.\/]+)(?::latest|\s*$)",
                "Unpinned or :latest base image tag in FROM",
                "Pin base images to a specific immutable version tag or SHA256 digest.",
            ),
            (
                "IAC003",
                "HIGH",
                r"(?:curl|wget)\s+[^\n|]+\|\s*(?:sh|bash|zsh)",
                "Dangerous execution pipe (curl/wget | sh)",
                "Download packages to file, verify checksums/signatures, and execute safely.",
            ),
            (
                "IAC004",
                "HIGH",
                r"^\s*(?:COPY|ADD)\s+[^\n]*(?:\.env|id_rsa|credentials|\.pem|\.key)",
                "Sensitive secret or credential file copied into container image",
                "Inject secrets at runtime via environment variables or secret managers.",
            ),
            (
                "IAC005",
                "MEDIUM",
                r"^\s*RUN\s+.*apt-get\s+install(?![^\n]*--no-install-recommends)",
                "Package manager install without cache minimization (--no-install-recommends)",
                "Use --no-install-recommends and clean /var/lib/apt/lists to minimize image size.",
            ),
            (
                "IAC006",
                "MEDIUM",
                r"^\s*EXPOSE\s+(?:21|22|23|25)\b",
                "Exposing legacy or dangerous administrative port (FTP/SSH/Telnet/SMTP)",
                "Do not run or expose legacy daemon services inside application containers.",
            ),
        ]

    def _patterns_compose(self) -> list[tuple[str, str, str, str, str]]:
        return [
            (
                "IAC010",
                "CRITICAL",
                r"^\s*privileged\s*:\s*true",
                "Container configured with privileged: true",
                "Remove privileged flag; grant only specific Linux capabilities via cap_add.",
            ),
            (
                "IAC011",
                "CRITICAL",
                r"['\"]?\/var\/run\/docker\.sock['\"]?\s*:",
                "Docker daemon socket mounted into container (/var/run/docker.sock)",
                "Avoid exposing docker.sock; container escape allows root takeover on host.",
            ),
            (
                "IAC012",
                "HIGH",
                r"^\s*network_mode\s*:\s*['\"]?host['\"]?",
                "Container shares host network namespace (network_mode: host)",
                "Use bridge or overlay networks to isolate container network interfaces.",
            ),
            (
                "IAC013",
                "HIGH",
                r"^\s*pid\s*:\s*['\"]?host['\"]?",
                "Container shares host process namespace (pid: host)",
                "Remove pid: host to maintain container process isolation.",
            ),
            (
                "IAC014",
                "HIGH",
                r"^\s*-\s*(?:PASSWORD|SECRET|TOKEN|API_KEY|PRIVATE_KEY)\s*=\s*[^\s]+",
                "Hardcoded sensitive secret in environment variable",
                "Load secret values from external environment or Docker secrets vault.",
            ),
            (
                "IAC015",
                "MEDIUM",
                r"^\s*cap_add\s*:\s*\n(?:\s*-\s*ALL|\s*-\s*SYS_ADMIN)",
                "Dangerous capability granted (SYS_ADMIN or ALL)",
                "Drop all capabilities by default and grant only minimum required caps.",
            ),
        ]

    def _patterns_k8s(self) -> list[tuple[str, str, str, str, str]]:
        return [
            (
                "IAC020",
                "HIGH",
                r"^\s*allowPrivilegeEscalation\s*:\s*true",
                "Container allows privilege escalation (allowPrivilegeEscalation: true)",
                "Set allowPrivilegeEscalation: false in securityContext.",
            ),
            (
                "IAC021",
                "HIGH",
                r"^\s*runAsNonRoot\s*:\s*false|^\s*runAsUser\s*:\s*0\b",
                "Pod permits running as root user (runAsNonRoot: false or runAsUser: 0)",
                "Set runAsNonRoot: true and specify a non-zero runAsUser ID in securityContext.",
            ),
            (
                "IAC022",
                "MEDIUM",
                r"^\s*readOnlyRootFilesystem\s*:\s*false",
                "Container root filesystem is writable",
                "Set readOnlyRootFilesystem: true and mount writable volumes only where required.",
            ),
        ]

    def _audit_content(
        self,
        content: str,
        file_path: Path,
    ) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        fname = file_path.name.lower()
        rel = str(file_path).replace("\\", "/")
        lines = content.splitlines()

        is_dockerfile = fname.startswith("dockerfile") or fname.endswith(".dockerfile")
        is_compose = "compose" in fname and fname.endswith((".yml", ".yaml"))
        is_k8s = fname.endswith((".yml", ".yaml")) and not is_compose

        if is_dockerfile:
            for rule_id, sev, pat, desc, rem in self._patterns_dockerfile():
                for idx, line in enumerate(lines, 1):
                    if re.search(pat, line, re.MULTILINE | re.IGNORECASE):
                        findings.append(
                            {
                                "rule_id": rule_id,
                                "severity": sev,
                                "file": rel,
                                "line": idx,
                                "description": desc,
                                "snippet": line.strip(),
                                "remediation": rem,
                            }
                        )

            has_user = any(re.match(r"^\s*USER\s+", line, re.I) for line in lines)
            if not has_user and lines:
                findings.append(
                    {
                        "rule_id": "IAC001",
                        "severity": "HIGH",
                        "file": rel,
                        "line": len(lines),
                        "description": "Dockerfile lacks USER instruction (defaults to root)",
                        "snippet": "Missing USER instruction",
                        "remediation": "Add a non-root USER before final ENTRYPOINT/CMD.",
                    }
                )

        if is_compose:
            for rule_id, sev, pat, desc, rem in self._patterns_compose():
                for idx, line in enumerate(lines, 1):
                    if re.search(pat, line, re.IGNORECASE):
                        findings.append(
                            {
                                "rule_id": rule_id,
                                "severity": sev,
                                "file": rel,
                                "line": idx,
                                "description": desc,
                                "snippet": line.strip(),
                                "remediation": rem,
                            }
                        )

        if is_k8s:
            is_k8s_manifest = "apiversion" in content.lower() and "kind" in content.lower()
            if is_k8s_manifest:
                for rule_id, sev, pat, desc, rem in self._patterns_k8s():
                    for idx, line in enumerate(lines, 1):
                        if re.search(pat, line, re.IGNORECASE):
                            findings.append(
                                {
                                    "rule_id": rule_id,
                                    "severity": sev,
                                    "file": rel,
                                    "line": idx,
                                    "description": desc,
                                    "snippet": line.strip(),
                                    "remediation": rem,
                                }
                            )
                has_sec_context = "securitycontext:" in content.lower()
                if not has_sec_context:
                    findings.append(
                        {
                            "rule_id": "IAC023",
                            "severity": "HIGH",
                            "file": rel,
                            "line": 1,
                            "description": "K8s manifest lacks securityContext definition",
                            "snippet": "Missing securityContext",
                            "remediation": "Set securityContext with runAsNonRoot: true.",
                        }
                    )

        return findings

    def _scan_target(self, target: str | Path) -> tuple[int, list[dict[str, Any]]]:
        p = Path(target).resolve()
        if p.is_file():
            try:
                content = p.read_text(encoding="utf-8", errors="ignore")
                res = self._audit_content(content, p)
                return len(res), res
            except Exception:
                return 0, []

        all_findings: list[dict[str, Any]] = []
        ignored = {".git", ".venv", "venv", "node_modules", "__pycache__"}
        for item in sorted(p.rglob("*")):
            if any(part in ignored for part in item.parts):
                continue
            fname = item.name.lower()
            is_target = (
                fname.startswith("dockerfile")
                or fname.endswith(".dockerfile")
                or ("compose" in fname and fname.endswith((".yml", ".yaml")))
                or (fname.endswith((".yml", ".yaml")) and "k8s" in str(item).lower())
            )
            if item.is_file() and is_target:
                try:
                    content = item.read_text(encoding="utf-8", errors="ignore")
                    all_findings.extend(self._audit_content(content, item))
                except Exception:
                    continue

        return len(all_findings), all_findings

    def _render_text(self, findings: list[dict[str, Any]], target: str) -> str:
        if not findings:
            return f"Sentinel IaC: No container/IaC misconfigurations in {target}."

        lines: list[str] = [
            f"Sentinel IaC: Found {len(findings)} container/IaC misconfiguration(s) in {target}:\n"
        ]
        for f in findings:
            lines.append(f"[{f['severity']}] {f['rule_id']} - {f['description']}")
            lines.append(f"  • File: {f['file']}:{f['line']}")
            lines.append(f"  • Snippet: {f['snippet']}")
            lines.append(f"  • Remediation: {f['remediation']}\n")
        return "\n".join(lines)

_auditor = IacAuditor()

def _scan(target: str | Path) -> tuple[int, list[dict[str, Any]]]:
    return _auditor._scan_target(target)

def _render(findings: list[dict[str, Any]], target: str) -> str:
    return _auditor._render_text(findings, target)
