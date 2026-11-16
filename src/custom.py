from __future__ import annotations
from pathlib import Path
from typing import Any
import re, urllib.parse, httpx, yaml

class CustomRuleAuditor:
    def _load_single_template(self, file_path: Path) -> dict[str, Any] | None:
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
            data = yaml.safe_load(content)
            if isinstance(data, dict) and ("id" in data or "info" in data):
                return data
        except Exception:
            return None
        return None

    def _load_templates(self, path_str: str | Path) -> list[tuple[Path, dict[str, Any]]]:
        p = Path(path_str).resolve()
        results: list[tuple[Path, dict[str, Any]]] = []
        if p.is_file():
            doc = self._load_single_template(p)
            if doc:
                results.append((p, doc))
            return results

        if p.is_dir():
            for item in sorted(p.rglob("*")):
                if item.suffix.lower() in (".yaml", ".yml"):
                    doc = self._load_single_template(item)
                    if doc:
                        results.append((item, doc))
        return results

    def _match_status(self, matcher: dict[str, Any], status_code: int) -> bool:
        expected = matcher.get("status", [])
        if isinstance(expected, int):
            expected = [expected]
        matched = status_code in expected
        return not matched if matcher.get("negative") else matched

    def _extract_part(self, matcher: dict[str, Any], headers_str: str, body: str) -> str:
        part = matcher.get("part", "body").lower()
        if part == "header":
            return headers_str
        if part == "all":
            return f"{headers_str}\n\n{body}"
        return body

    def _match_words(self, matcher: dict[str, Any], content: str) -> bool:
        words = matcher.get("words", [])
        if isinstance(words, str):
            words = [words]
        if not words:
            return False
        cond = matcher.get("condition", "or").lower()
        case_sensitive = matcher.get("case-sensitive", False)
        target = content if case_sensitive else content.lower()

        if cond == "and":
            matched = all((w if case_sensitive else w.lower()) in target for w in words)
        else:
            matched = any((w if case_sensitive else w.lower()) in target for w in words)

        return not matched if matcher.get("negative") else matched

    def _match_regex(self, matcher: dict[str, Any], content: str) -> bool:
        patterns = matcher.get("regex", [])
        if isinstance(patterns, str):
            patterns = [patterns]
        if not patterns:
            return False
        cond = matcher.get("condition", "or").lower()

        if cond == "and":
            matched = all(bool(re.search(pat, content)) for pat in patterns)
        else:
            matched = any(bool(re.search(pat, content)) for pat in patterns)

        return not matched if matcher.get("negative") else matched

    def _evaluate_matcher(
        self,
        matcher: dict[str, Any],
        status_code: int,
        headers_str: str,
        body: str,
    ) -> bool:
        mtype = matcher.get("type", "word").lower()
        if mtype == "status":
            return self._match_status(matcher, status_code)
        content = self._extract_part(matcher, headers_str, body)
        if mtype == "word":
            return self._match_words(matcher, content)
        if mtype == "regex":
            return self._match_regex(matcher, content)
        return False

    def _evaluate_all_matchers(
        self,
        matchers: list[dict[str, Any]],
        condition: str,
        status_code: int,
        headers_str: str,
        body: str,
    ) -> bool:
        if not matchers:
            return False
        cond = condition.lower()
        if cond == "and":
            return all(
                self._evaluate_matcher(m, status_code, headers_str, body)
                for m in matchers
            )
        return any(
            self._evaluate_matcher(m, status_code, headers_str, body)
            for m in matchers
        )

    def _build_url(self, base_url: str, path_pattern: str) -> str:
        clean_base = base_url.rstrip("/")
        if "{{BaseURL}}" in path_pattern:
            return path_pattern.replace("{{BaseURL}}", clean_base)
        if "{{RootURL}}" in path_pattern:
            parsed = urllib.parse.urlparse(clean_base)
            root = f"{parsed.scheme}://{parsed.netloc}"
            return path_pattern.replace("{{RootURL}}", root)
        if path_pattern.startswith("http://") or path_pattern.startswith("https://"):
            return path_pattern
        return f"{clean_base}/{path_pattern.lstrip('/')}"

    def _execute_http_block(
        self,
        base_url: str,
        http_block: dict[str, Any],
        client: httpx.Client,
        rule_meta: dict[str, Any],
    ) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        method = http_block.get("method", "GET").upper()
        paths = http_block.get("path", ["/"])
        if isinstance(paths, str):
            paths = [paths]

        headers = http_block.get("headers", {})
        body = http_block.get("body")
        matchers = http_block.get("matchers", [])
        m_cond = http_block.get(
            "matchers-condition", http_block.get("matchers_condition", "and")
        )

        for p_pat in paths:
            target_url = self._build_url(base_url, p_pat)
            try:
                resp = client.request(
                    method=method,
                    url=target_url,
                    headers=headers,
                    content=body,
                )
                headers_str = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
                body_str = resp.text

                if self._evaluate_all_matchers(
                    matchers, m_cond, resp.status_code, headers_str, body_str
                ):
                    findings.append(
                        {
                            "id": rule_meta.get("id", "CUSTOM-001"),
                            "name": rule_meta.get("name", "Custom Rule Matched"),
                            "severity": rule_meta.get("severity", "MEDIUM").upper(),
                            "url": target_url,
                            "template": rule_meta.get("template_file", ""),
                            "description": rule_meta.get("description", "Rule match detected."),
                            "status_code": resp.status_code,
                        }
                    )
            except Exception:
                continue

        return findings

    def _scan_target(
        self,
        target: str,
        template_path: str | Path,
        timeout: float = 8.0,
    ) -> tuple[int, list[dict[str, Any]], int]:
        clean_target = target.strip()
        if not clean_target.startswith(("http://", "https://")):
            clean_target = f"http://{clean_target}"

        loaded = self._load_templates(template_path)
        if not loaded:
            return 0, [], 0

        findings: list[dict[str, Any]] = []
        headers = {"User-Agent": "Varethic/Sentinel, Github"}

        with httpx.Client(
            timeout=timeout,
            follow_redirects=True,
            headers=headers,
        ) as client:
            for t_path, doc in loaded:
                rule_id = doc.get("id", t_path.stem)
                info = doc.get("info", {}) if isinstance(doc.get("info"), dict) else {}
                rule_meta = {
                    "id": rule_id,
                    "name": info.get("name", rule_id),
                    "severity": info.get("severity", "MEDIUM"),
                    "description": info.get("description", ""),
                    "template_file": str(t_path).replace("\\", "/"),
                }
                http_blocks = doc.get("http", [])
                if isinstance(http_blocks, dict):
                    http_blocks = [http_blocks]
                for block in http_blocks:
                    if isinstance(block, dict):
                        findings.extend(
                            self._execute_http_block(
                                clean_target, block, client, rule_meta
                            )
                        )

        return len(findings), findings, len(loaded)

    def _render_text(
        self,
        findings: list[dict[str, Any]],
        template_count: int,
        target: str,
    ) -> str:
        if not findings:
            return (
                f"Sentinel Custom Rules: 0 matches found for {target} "
                f"across {template_count} template(s)."
            )

        lines: list[str] = [
            f"Sentinel Custom Rules: Found {len(findings)} match(es) for {target} "
            f"across {template_count} template(s):\n"
        ]
        for f in findings:
            lines.append(f"[{f['severity']}] {f['id']} - {f['name']}")
            lines.append(f"  • URL: {f['url']} (HTTP {f['status_code']})")
            lines.append(f"  • Template: {f['template']}")
            if f["description"]:
                lines.append(f"  • Description: {f['description']}")
            lines.append("")
        return "\n".join(lines).rstrip()

_auditor = CustomRuleAuditor()

def _scan(
    target: str,
    template: str | Path,
    timeout: float = 8.0,
) -> tuple[int, list[dict[str, Any]], int]:
    return _auditor._scan_target(target, template, timeout=timeout)

def _render(
    findings: list[dict[str, Any]],
    template_count: int,
    target: str,
) -> str:
    return _auditor._render_text(findings, template_count, target)
