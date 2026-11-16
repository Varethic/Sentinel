from __future__ import annotations
import json, re
from pathlib import Path
from typing import Any

class Config:
    def _advisories(self) -> list[dict[str, Any]]:
        return [
            {
                "package": "requests",
                "ecosystem": "python",
                "max_vulnerable": "2.31.0",
                "fixed": "2.31.0",
                "cve": "CVE-2023-32681",
                "severity": "HIGH",
                "title": "Proxy-Authorization Header Leak On Cross-Origin Redirect",
            },
            {
                "package": "urllib3",
                "ecosystem": "python",
                "max_vulnerable": "2.0.7",
                "fixed": "2.0.7",
                "cve": "CVE-2023-45803",
                "severity": "HIGH",
                "title": "HTTP Request Body Not Stripped On 303 Redirect",
            },
            {
                "package": "django",
                "ecosystem": "python",
                "max_vulnerable": "4.2.16",
                "fixed": "4.2.16",
                "cve": "CVE-2024-45230",
                "severity": "HIGH",
                "title": "Potential Denial-of-Service In Email Sending and Auth",
            },
            {
                "package": "flask",
                "ecosystem": "python",
                "max_vulnerable": "2.2.5",
                "fixed": "2.2.5",
                "cve": "CVE-2023-30861",
                "severity": "HIGH",
                "title": "Session Cookie Disclosure via Cache Poisoning",
            },
            {
                "package": "jinja2",
                "ecosystem": "python",
                "max_vulnerable": "3.1.4",
                "fixed": "3.1.4",
                "cve": "CVE-2024-34064",
                "severity": "HIGH",
                "title": "HTML Attribute Injection in Dynamic Attribute Rendering",
            },
            {
                "package": "pyyaml",
                "ecosystem": "python",
                "max_vulnerable": "5.4.0",
                "fixed": "5.4",
                "cve": "CVE-2020-14343",
                "severity": "CRITICAL",
                "title": "Arbitrary Code Execution via FullLoader Deserialization",
            },
            {
                "package": "cryptography",
                "ecosystem": "python",
                "max_vulnerable": "42.0.4",
                "fixed": "42.0.4",
                "cve": "CVE-2024-26130",
                "severity": "HIGH",
                "title": "NULL Pointer Dereference in PKCS#12 Key Parsing",
            },
            {
                "package": "werkzeug",
                "ecosystem": "python",
                "max_vulnerable": "3.0.3",
                "fixed": "3.0.3",
                "cve": "CVE-2024-34069",
                "severity": "HIGH",
                "title": "Remote Code Execution in Werkzeug Debugger Console",
            },
            {
                "package": "aiohttp",
                "ecosystem": "python",
                "max_vulnerable": "3.9.4",
                "fixed": "3.9.4",
                "cve": "CVE-2024-27306",
                "severity": "HIGH",
                "title": "Path Traversal in Static File Serving Handler",
            },
            {
                "package": "sqlparse",
                "ecosystem": "python",
                "max_vulnerable": "0.5.0",
                "fixed": "0.5.0",
                "cve": "CVE-2024-4340",
                "severity": "HIGH",
                "title": "Unbounded Recursion Denial-of-Service in Query Parser",
            },
            {
                "package": "axios",
                "ecosystem": "npm",
                "max_vulnerable": "1.7.4",
                "fixed": "1.7.4",
                "cve": "CVE-2024-39338",
                "severity": "HIGH",
                "title": "Server-Side Request Forgery via Relative URL Handling",
            },
            {
                "package": "express",
                "ecosystem": "npm",
                "max_vulnerable": "4.19.2",
                "fixed": "4.19.2",
                "cve": "CVE-2024-29041",
                "severity": "HIGH",
                "title": "Open Redirect and Cross-Site Scripting via Malformed URL",
            },
            {
                "package": "lodash",
                "ecosystem": "npm",
                "max_vulnerable": "4.17.21",
                "fixed": "4.17.21",
                "cve": "CVE-2021-23337",
                "severity": "CRITICAL",
                "title": "Command Injection via Prototype Pollution in template()",
            },
            {
                "package": "jsonwebtoken",
                "ecosystem": "npm",
                "max_vulnerable": "9.0.0",
                "fixed": "9.0.0",
                "cve": "CVE-2022-23529",
                "severity": "HIGH",
                "title": "Arbitrary File Write and Execution in Key Verification",
            },
            {
                "package": "ws",
                "ecosystem": "npm",
                "max_vulnerable": "8.17.1",
                "fixed": "8.17.1",
                "cve": "CVE-2024-37890",
                "severity": "HIGH",
                "title": "Regular Expression Denial-of-Service in Header Parser",
            },
        ]

class ScaScanner:
    def __init__(self) -> None:
        self.cfg = Config()

    def _parse_version(self, text: str) -> tuple[int, ...]:
        clean = re.sub(r"[^\d.]", "", text.strip())
        parts: list[int] = []
        for p in clean.split("."):
            if p.isdigit():
                parts.append(int(p))
        return tuple(parts) if parts else (0,)

    def _is_vulnerable(self, installed: str, max_vuln: str) -> bool:
        v_inst = self._parse_version(installed)
        v_max = self._parse_version(max_vuln)
        return v_inst < v_max

    def _parse_requirements(self, content: str) -> list[tuple[str, str]]:
        deps: list[tuple[str, str]] = []
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith(("-", "#", ";")):
                continue
            pattern = r"^([a-zA-Z0-9_\-\.]+)\s*(?:==|<=|>=|~=|<|>)\s*([0-9a-zA-Z\.\-]+)"
            match = re.match(pattern, line)
            if match:
                deps.append((match.group(1).lower(), match.group(2)))
        return deps

    def _parse_package_json(self, content: str) -> list[tuple[str, str]]:
        deps: list[tuple[str, str]] = []
        try:
            data = json.loads(content)
        except Exception:
            return deps
        for sec in ("dependencies", "devDependencies"):
            sec_dict = data.get(sec, {})
            if isinstance(sec_dict, dict):
                for pkg, ver in sec_dict.items():
                    clean_ver = re.sub(r"^[^\d]*", "", str(ver))
                    if clean_ver:
                        deps.append((pkg.lower(), clean_ver))
        return deps

    def _scan_file(self, file_path: Path) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        fname = file_path.name.lower()
        try:
            content = file_path.read_text(encoding="utf-8")
        except Exception:
            return findings

        parsed_deps: list[tuple[str, str]] = []
        is_txt = fname.endswith(".txt") or "req" in fname or "deps" in fname
        if is_txt:
            parsed_deps = self._parse_requirements(content)
        elif fname.endswith(".json") or "package" in fname:
            parsed_deps = self._parse_package_json(content)

        advisories = self.cfg._advisories()
        rel_path = str(file_path).replace("\\", "/")

        for pkg, installed_ver in parsed_deps:
            for adv in advisories:
                match_pkg = adv["package"] == pkg
                if match_pkg and self._is_vulnerable(installed_ver, adv["max_vulnerable"]):
                    findings.append(
                        {
                            "file": rel_path,
                            "package": pkg,
                            "installed": installed_ver,
                            "fixed": adv["fixed"],
                            "cve": adv["cve"],
                            "severity": adv["severity"],
                            "title": adv["title"],
                        }
                    )
        return findings

    def _scan_target(self, target: str | Path) -> tuple[int, list[dict[str, Any]]]:
        p = Path(target).resolve()
        if p.is_file():
            res = self._scan_file(p)
            return len(res), res

        all_findings: list[dict[str, Any]] = []
        ignored = {".git", ".venv", "venv", "node_modules", "__pycache__"}
        for item in sorted(p.rglob("*")):
            if any(part in ignored for part in item.parts):
                continue
            if item.is_file() and item.name.lower() in (
                "requirements.txt",
                "requirements-dev.txt",
                "deps.txt",
                "package.json",
            ):
                all_findings.extend(self._scan_file(item))

        return len(all_findings), all_findings

    def _render_text(self, findings: list[dict[str, Any]], target: str) -> str:
        if not findings:
            return f"Sentinel SCA: No vulnerable dependencies detected in {target}."
        lines: list[str] = [
            f"Sentinel SCA: Found {len(findings)} vulnerable dependency(ies) in {target}:\n"
        ]
        for f in findings:
            lines.append(
                f"[{f['severity']}] {f['package']} {f['installed']} ({f['cve']})"
            )
            lines.append(f"  • Title: {f['title']}")
            lines.append(f"  • Location: {f['file']}")
            lines.append(f"  • Recommended Fix: Upgrade {f['package']} >= {f['fixed']}\n")
        return "\n".join(lines)

_scanner = ScaScanner()

def _scan(target: str | Path) -> tuple[int, list[dict[str, Any]]]:
    return _scanner._scan_target(target)

def _render(findings: list[dict[str, Any]], target: str) -> str:
    return _scanner._render_text(findings, target)
