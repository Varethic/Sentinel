from __future__ import annotations
import json, re, urllib.parse
from pathlib import Path
from typing import Any
import httpx

class OpenApiAuditor:
    def _load_spec(
        self,
        source: str,
        headers: dict[str, str] | None = None,
        timeout: float = 10.0,
    ) -> tuple[dict[str, Any] | None, str]:
        p = Path(source).resolve()
        if p.is_file():
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
                return data, str(p)
            except Exception as exc:
                return None, f"Failed to parse JSON file {p}: {exc}"

        parsed = urllib.parse.urlparse(source)
        if parsed.scheme in ("http", "https"):
            urls = [source]
            if not source.endswith((".json", ".yaml")):
                base = source.rstrip("/")
                urls.extend(
                    [
                        f"{base}/openapi.json",
                        f"{base}/swagger.json",
                        f"{base}/api/v1/openapi.json",
                    ]
                )
            client_headers = {"Accept": "application/json"}
            if headers:
                client_headers.update(headers)

            with httpx.Client(timeout=timeout, follow_redirects=True) as client:
                for candidate in urls:
                    try:
                        resp = client.get(candidate, headers=client_headers)
                        ct = resp.headers.get("content-type", "")
                        if resp.status_code == 200 and "application/json" in ct:
                            return resp.json(), candidate
                        try:
                            json_data = resp.json()
                            markers = ("openapi", "swagger", "paths")
                            if any(m in json_data for m in markers):
                                return json_data, candidate
                        except Exception:
                            continue
                    except Exception:
                        continue
            return None, f"Could not retrieve OpenAPI specification from {source}"

        return None, f"Specification source not found: {source}"

    def _extract_schema_properties(
        self,
        schema: dict[str, Any],
        components: dict[str, Any],
    ) -> set[str]:
        props: set[str] = set()
        ref = schema.get("$ref", "")
        if ref.startswith("#/components/schemas/"):
            schema_name = ref.split("/")[-1]
            schema = components.get(schema_name, {})

        for k, v in schema.get("properties", {}).items():
            props.add(k.lower())
            if isinstance(v, dict) and "$ref" in v:
                props.update(self._extract_schema_properties(v, components))

        for sub in schema.get("allOf", []) + schema.get("anyOf", []):
            if isinstance(sub, dict):
                props.update(self._extract_schema_properties(sub, components))
        return props

    def _audit_spec(self, spec: dict[str, Any], origin: str) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        paths: dict[str, Any] = spec.get("paths", {})
        components = spec.get("components", {}).get("schemas", {})
        global_security = spec.get("security", [])

        sensitive_kw = ("admin", "internal", "user", "billing", "account", "token", "auth")
        mass_assign_kw = {
            "role", "roles", "is_admin", "is_superuser", "permissions",
            "balance", "credits", "status", "verified", "plan",
        }
        ssrf_param_kw = {"url", "callback", "webhook", "target", "redirect", "uri"}
        pagination_kw = {"limit", "size", "page", "per_page", "offset"}

        for path_str, path_item in paths.items():
            if not isinstance(path_item, dict):
                continue
            for method, op in path_item.items():
                if method.lower() not in ("get", "post", "put", "patch", "delete"):
                    continue
                if not isinstance(op, dict):
                    continue

                sec = op.get("security", global_security)
                has_auth = bool(sec)

                has_object_id = bool(
                    re.search(r"\{[a-zA-Z0-9_-]*(?:id|key|uuid|pk)\}", path_str, re.I)
                )
                if has_object_id and not has_auth:
                    findings.append(
                        {
                            "rule_id": "API1:2023",
                            "severity": "CRITICAL",
                            "title": "Broken Object Level Authorization (BOLA / IDOR)",
                            "endpoint": f"{method.upper()} {path_str}",
                            "detail": f"Path parameter in {path_str} lacks security requirements.",
                            "remediation": "Enforce object ownership validation and auth scope.",
                        }
                    )

                is_sensitive_path = any(kw in path_str.lower() for kw in sensitive_kw)
                if is_sensitive_path and not has_auth:
                    findings.append(
                        {
                            "rule_id": "API2:2023",
                            "severity": "HIGH",
                            "title": "Broken Authentication on Sensitive Route",
                            "endpoint": f"{method.upper()} {path_str}",
                            "detail": f"Sensitive route {path_str} has no authentication scheme.",
                            "remediation": "Enforce Bearer or API key security requirement.",
                        }
                    )

                if method.lower() in ("post", "put", "patch"):
                    req_body = op.get("requestBody", {})
                    content_dict = req_body.get("content", {})
                    for media_spec in content_dict.values():
                        body_schema = media_spec.get("schema", {})
                        props = self._extract_schema_properties(body_schema, components)
                        dangerous_props = props.intersection(mass_assign_kw)
                        if dangerous_props:
                            bad_fields = ", ".join(sorted(dangerous_props))
                            findings.append(
                                {
                                    "rule_id": "API3:2023",
                                    "severity": "HIGH",
                                    "title": "Mass Assignment Vulnerability",
                                    "endpoint": f"{method.upper()} {path_str}",
                                    "detail": f"Body accepts privileged field: {bad_fields}",
                                    "remediation": "Bind input to strict DTOs with allowlist.",
                                }
                            )

                params = op.get("parameters", []) + path_item.get("parameters", [])
                param_names = {p.get("name", "").lower() for p in params if isinstance(p, dict)}

                is_list_get = method.lower() == "get" and not has_object_id
                if is_list_get and not param_names.intersection(pagination_kw):
                    findings.append(
                        {
                            "rule_id": "API4:2023",
                            "severity": "MEDIUM",
                            "title": "Unrestricted Resource Consumption",
                            "endpoint": f"{method.upper()} {path_str}",
                            "detail": f"List endpoint {path_str} lacks pagination parameters.",
                            "remediation": "Enforce max pagination bounds and rate-limiting.",
                        }
                    )

                ssrf_matches = param_names.intersection(ssrf_param_kw)
                if ssrf_matches:
                    match_str = ", ".join(sorted(ssrf_matches))
                    findings.append(
                        {
                            "rule_id": "API7:2023",
                            "severity": "HIGH",
                            "title": "Server-Side Request Forgery (SSRF) Risk",
                            "endpoint": f"{method.upper()} {path_str}",
                            "detail": f"Parameter(s) {match_str} accept arbitrary URLs.",
                            "remediation": "Validate destination hostnames against an allowlist.",
                        }
                    )

        servers = spec.get("servers", [])
        for s in servers:
            s_url = s.get("url", "")
            is_insecure = (
                s_url.startswith("http://")
                and not s_url.startswith("http://localhost")
                and not s_url.startswith("http://127.0.0.1")
            )
            if is_insecure:
                findings.append(
                    {
                        "rule_id": "API8:2023",
                        "severity": "MEDIUM",
                        "title": "Security Misconfiguration (HTTP Server)",
                        "endpoint": s_url,
                        "detail": f"Production API server declares unencrypted URL {s_url}.",
                        "remediation": "Migrate all public API endpoints to HTTPS with HSTS.",
                    }
                )

        return findings

    def _audit(
        self,
        source: str,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, list[dict[str, Any]], str]:
        spec, actual_origin = self._load_spec(source, headers=headers)
        if spec is None:
            return 0, [], actual_origin

        findings = self._audit_spec(spec, actual_origin)
        return len(findings), findings, actual_origin

    def _render_text(self, findings: list[dict[str, Any]], origin: str) -> str:
        if not findings:
            return f"Sentinel OpenAPI: Spec at {origin} has 0 API security issues."

        lines: list[str] = [
            f"Sentinel OpenAPI: Found {len(findings)} security gap(s) in {origin}:\n"
        ]
        for f in findings:
            lines.append(f"[{f['severity']}] {f['rule_id']} - {f['title']}")
            lines.append(f"  • Endpoint: {f['endpoint']}")
            lines.append(f"  • Detail: {f['detail']}")
            lines.append(f"  • Remediation: {f['remediation']}\n")
        return "\n".join(lines)

_auditor = OpenApiAuditor()

def _audit(
    source: str,
    headers: dict[str, str] | None = None,
) -> tuple[int, list[dict[str, Any]], str]:
    return _auditor._audit(source, headers=headers)

def _render(findings: list[dict[str, Any]], origin: str) -> str:
    return _auditor._render_text(findings, origin)
