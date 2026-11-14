"""Full-stack web and container configuration static analyzer (WEB001-WEB005).

Provides static source analysis across JavaScript, TypeScript, PHP, HTML,
environment files (.env), Dockerfiles, and Docker Compose configurations.
"""

from __future__ import annotations

from pathlib import Path

from src.core.engine import Finding, SourceFile, _is_suppressed_line
from src.core.loader import Rule, _rules_for

ANALYZER_NAME: str = "webfile"

_SNIPPET_LIMIT: int = 160

_PLACEHOLDERS: frozenset[str] = frozenset(
    {
        "",
        "changeme",
        "change_me",
        "change-me",
        "placeholder",
        "your_secret_here",
        "your-secret-here",
        "your_api_key",
        "your-api-key",
        "xxx",
        "xxxx",
        "todo",
        "test",
        "fake",
        "dummy",
        "none",
        "null",
        "redacted",
        "secret",
        "password",
        "undefined",
        "example",
    }
)

_SECRET_KEYWORDS: frozenset[str] = frozenset(
    {
        "api_key",
        "apikey",
        "secret",
        "secret_key",
        "password",
        "passwd",
        "token",
        "access_token",
        "private_key",
        "auth_key",
        "db_pass",
        "database_password",
    }
)

_PHP_SINKS: tuple[str, ...] = ("eval", "shell_exec", "system", "passthru", "exec")
_PHP_SUPERGLOBALS: tuple[str, ...] = ("$_get", "$_post", "$_request", "$_cookie", "$_server")


def _snippet_text(line: str) -> str:
    """Format and truncate a source line for reporting."""
    stripped = line.strip()
    if len(stripped) > _SNIPPET_LIMIT:
        return stripped[: _SNIPPET_LIMIT - 3].rstrip() + "..."
    return stripped


def _is_placeholder_secret(value: str) -> bool:
    """Return True if a secret value is a placeholder or template variable."""
    val = value.strip().strip("'\"`").lower()
    if not val or val in _PLACEHOLDERS:
        return True
    if val.startswith("${") and val.endswith("}"):
        return True
    if val.startswith("<") and val.endswith(">"):
        return True
    if val.startswith("process.env.") or val.startswith("getenv("):
        return True
    return False


def _check_dom_xss(target: SourceFile, rule: Rule) -> list[Finding]:
    """Inspect JS/TS/HTML source lines for client-side XSS sinks (WEB001)."""
    findings: list[Finding] = []
    ext = target.path.suffix.lower()
    if ext not in {".js", ".ts", ".jsx", ".tsx", ".html"}:
        return findings

    for lineno, line in enumerate(target.lines, start=1):
        if _is_suppressed_line(line):
            continue
        lowered = line.lower()
        matched_desc: str | None = None

        if "dangerouslysetinnerhtml" in lowered:
            matched_desc = "Unsafe React sink 'dangerouslySetInnerHTML' can lead to DOM XSS"
        elif "innerhtml" in lowered and "=" in line:
            idx = lowered.find("innerhtml")
            after = line[idx + 9 :].lstrip()
            if after.startswith("="):
                matched_desc = "Unsafe DOM sink 'innerHTML =' assignment can lead to DOM XSS"
        elif "outerhtml" in lowered and "=" in line:
            idx = lowered.find("outerhtml")
            after = line[idx + 9 :].lstrip()
            if after.startswith("="):
                matched_desc = "Unsafe DOM sink 'outerHTML =' assignment can lead to DOM XSS"
        elif "document.write" in lowered and "(" in line:
            matched_desc = "Unsafe DOM sink 'document.write()' can lead to DOM XSS"
        elif "eval(" in line.replace(" ", ""):
            matched_desc = "Unsafe dynamic 'eval()' call can execute untrusted JavaScript"

        if matched_desc:
            findings.append(
                Finding(
                    rule_id=rule.rule_id,
                    rule_name=rule.name,
                    severity=rule.severity,
                    category=rule.category,
                    cwe_id=rule.cwe_id,
                    cve=rule.cve,
                    cve_date=rule.cve_date,
                    file_path=target.display_path,
                    line_number=lineno,
                    column=1,
                    code_snippet=_snippet_text(line),
                    message=matched_desc,
                    remediation=rule.remediation_example,
                )
            )
    return findings


def _check_secrets(target: SourceFile, rule: Rule) -> list[Finding]:
    """Inspect .env, configs, and source files for hardcoded secrets (WEB002)."""
    findings: list[Finding] = []
    filename = target.path.name.lower()
    ext = target.path.suffix.lower()

    if any(token in filename for token in (".example", ".template", ".sample")):
        return findings

    is_env = ext == ".env" or filename.startswith(".env")
    is_docker = filename == "dockerfile" or filename.startswith("dockerfile.")
    is_compose = filename in {"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"}
    is_code = ext in {".js", ".ts", ".jsx", ".tsx", ".php"}

    if not (is_env or is_docker or is_compose or is_code):
        return findings

    for lineno, line in enumerate(target.lines, start=1):
        if _is_suppressed_line(line):
            continue
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("//"):
            continue

        if is_env:
            if "=" in stripped:
                key, _, val = stripped.partition("=")
                k_clean = key.strip().lower().replace("export ", "")
                v_clean = val.strip().strip("'\"`")
                if any(kw in k_clean for kw in _SECRET_KEYWORDS):
                    if not _is_placeholder_secret(v_clean) and len(v_clean) >= 6:
                        findings.append(
                            Finding(
                                rule_id=rule.rule_id,
                                rule_name=rule.name,
                                severity=rule.severity,
                                category=rule.category,
                                cwe_id=rule.cwe_id,
                                cve=rule.cve,
                                cve_date=rule.cve_date,
                                file_path=target.display_path,
                                line_number=lineno,
                                column=1,
                                code_snippet=_snippet_text(line),
                                message=f"Hardcoded credential '{key.strip()}' committed in environment file",
                                remediation=rule.remediation_example,
                            )
                        )

        elif is_docker:
            lowered = stripped.lower()
            if lowered.startswith("env ") or lowered.startswith("arg "):
                remainder = stripped[4:].strip()
                sep = "=" if "=" in remainder else " "
                key, _, val = remainder.partition(sep)
                k_clean = key.strip().lower()
                v_clean = val.strip().strip("'\"`")
                if any(kw in k_clean for kw in _SECRET_KEYWORDS):
                    if not _is_placeholder_secret(v_clean) and len(v_clean) >= 6:
                        findings.append(
                            Finding(
                                rule_id=rule.rule_id,
                                rule_name=rule.name,
                                severity=rule.severity,
                                category=rule.category,
                                cwe_id=rule.cwe_id,
                                cve=rule.cve,
                                cve_date=rule.cve_date,
                                file_path=target.display_path,
                                line_number=lineno,
                                column=1,
                                code_snippet=_snippet_text(line),
                                message=f"Hardcoded secret in Dockerfile instruction: '{key.strip()}'",
                                remediation=rule.remediation_example,
                            )
                        )

        elif is_compose:
            sep = "=" if "=" in stripped else (":" if ":" in stripped else None)
            if sep:
                raw_k, _, raw_v = stripped.lstrip("- ").partition(sep)
                k_clean = raw_k.strip().lower()
                v_clean = raw_v.strip().strip("'\"`")
                if any(kw in k_clean for kw in _SECRET_KEYWORDS):
                    if not _is_placeholder_secret(v_clean) and len(v_clean) >= 6:
                        findings.append(
                            Finding(
                                rule_id=rule.rule_id,
                                rule_name=rule.name,
                                severity=rule.severity,
                                category=rule.category,
                                cwe_id=rule.cwe_id,
                                cve=rule.cve,
                                cve_date=rule.cve_date,
                                file_path=target.display_path,
                                line_number=lineno,
                                column=1,
                                code_snippet=_snippet_text(line),
                                message=f"Hardcoded credential '{raw_k.strip()}' in docker-compose environment",
                                remediation=rule.remediation_example,
                            )
                        )

        elif is_code:
            sep = "=" if "=" in stripped else (":" if ":" in stripped else None)
            if sep:
                left, _, right = stripped.partition(sep)
                left_clean = left.strip().lower()
                right_clean = right.strip()
                if any(kw in left_clean for kw in _SECRET_KEYWORDS):
                    if (right_clean.startswith('"') and '"' in right_clean[1:]) or (
                        right_clean.startswith("'") and "'" in right_clean[1:]
                    ):
                        quote = right_clean[0]
                        secret_val = right_clean[1:].split(quote, 1)[0]
                        if not _is_placeholder_secret(secret_val) and len(secret_val) >= 8:
                            findings.append(
                                Finding(
                                    rule_id=rule.rule_id,
                                    rule_name=rule.name,
                                    severity=rule.severity,
                                    category=rule.category,
                                    cwe_id=rule.cwe_id,
                                    cve=rule.cve,
                                    cve_date=rule.cve_date,
                                    file_path=target.display_path,
                                    line_number=lineno,
                                    column=1,
                                    code_snippet=_snippet_text(line),
                                    message=f"Hardcoded secret literal assigned to '{left.strip()}'",
                                    remediation=rule.remediation_example,
                                )
                            )
    return findings


def _check_php_rce(target: SourceFile, rule: Rule) -> list[Finding]:
    """Inspect PHP source lines for dynamic eval and shell execution sinks (WEB003)."""
    findings: list[Finding] = []
    if target.path.suffix.lower() != ".php":
        return findings

    for lineno, line in enumerate(target.lines, start=1):
        if _is_suppressed_line(line):
            continue
        lowered = line.lower()
        compact = line.replace(" ", "")

        for sink in _PHP_SINKS:
            if f"{sink}(" in compact.lower():
                if any(sg in lowered for sg in _PHP_SUPERGLOBALS):
                    findings.append(
                        Finding(
                            rule_id=rule.rule_id,
                            rule_name=rule.name,
                            severity=rule.severity,
                            category=rule.category,
                            cwe_id=rule.cwe_id,
                            cve=rule.cve,
                            cve_date=rule.cve_date,
                            file_path=target.display_path,
                            line_number=lineno,
                            column=1,
                            code_snippet=_snippet_text(line),
                            message=f"Direct execution of PHP superglobal request parameter in shell/eval sink ({sink})",
                            remediation=rule.remediation_example,
                        )
                    )
                    break
                if f"{sink}($" in compact.lower():
                    findings.append(
                        Finding(
                            rule_id=rule.rule_id,
                            rule_name=rule.name,
                            severity=rule.severity,
                            category=rule.category,
                            cwe_id=rule.cwe_id,
                            cve=rule.cve,
                            cve_date=rule.cve_date,
                            file_path=target.display_path,
                            line_number=lineno,
                            column=1,
                            code_snippet=_snippet_text(line),
                            message=f"Dynamic variable passed to PHP shell/eval sink ({sink}) without visible escaping",
                            remediation=rule.remediation_example,
                        )
                    )
                    break
    return findings


def _check_dockerfile_privilege(target: SourceFile, rule: Rule) -> list[Finding]:
    """Inspect Dockerfiles for root execution or missing USER instructions (WEB004)."""
    findings: list[Finding] = []
    filename = target.path.name.lower()
    if filename != "dockerfile" and not filename.startswith("dockerfile."):
        return findings

    has_from = False
    last_user: str | None = None
    root_user_lineno: int | None = None

    for lineno, line in enumerate(target.lines, start=1):
        if _is_suppressed_line(line):
            continue
        stripped = line.strip()
        lowered = stripped.lower()
        if lowered.startswith("from ") or lowered == "from":
            has_from = True
        if lowered.startswith("user "):
            user_val = stripped[5:].strip().lower()
            last_user = user_val
            if user_val in {"root", "0"}:
                root_user_lineno = lineno
                findings.append(
                    Finding(
                        rule_id=rule.rule_id,
                        rule_name=rule.name,
                        severity=rule.severity,
                        category=rule.category,
                        cwe_id=rule.cwe_id,
                        cve=rule.cve,
                        cve_date=rule.cve_date,
                        file_path=target.display_path,
                        line_number=lineno,
                        column=1,
                        code_snippet=_snippet_text(line),
                        message="Dockerfile explicitly sets container execution user to 'USER root'",
                        remediation=rule.remediation_example,
                    )
                )

    if has_from and (last_user is None or last_user in {"root", "0"}):
        if not root_user_lineno:
            findings.append(
                Finding(
                    rule_id=rule.rule_id,
                    rule_name=rule.name,
                    severity=rule.severity,
                    category=rule.category,
                    cwe_id=rule.cwe_id,
                    cve=rule.cve,
                    cve_date=rule.cve_date,
                    file_path=target.display_path,
                    line_number=1,
                    column=1,
                    code_snippet=_snippet_text(target.lines[0]) if target.lines else "",
                    message="Dockerfile does not declare a non-root USER instruction; container processes run as root by default",
                    remediation=rule.remediation_example,
                )
            )

    return findings


def _check_dockerfile_images(target: SourceFile, rule: Rule) -> list[Finding]:
    """Inspect Dockerfiles for remote ADD instructions and unpinned base images (WEB005)."""
    findings: list[Finding] = []
    filename = target.path.name.lower()
    if filename != "dockerfile" and not filename.startswith("dockerfile."):
        return findings

    stages: set[str] = set()

    for lineno, line in enumerate(target.lines, start=1):
        if _is_suppressed_line(line):
            continue
        stripped = line.strip()
        lowered = stripped.lower()

        if lowered.startswith("add ") and ("http://" in lowered or "https://" in lowered):
            findings.append(
                Finding(
                    rule_id=rule.rule_id,
                    rule_name=rule.name,
                    severity=rule.severity,
                    category=rule.category,
                    cwe_id=rule.cwe_id,
                    cve=rule.cve,
                    cve_date=rule.cve_date,
                    file_path=target.display_path,
                    line_number=lineno,
                    column=1,
                    code_snippet=_snippet_text(line),
                    message="Insecure remote file download via 'ADD http(s)://'; use COPY or curl with checksum verification",
                    remediation=rule.remediation_example,
                )
            )

        if lowered.startswith("from "):
            tokens = stripped.split()
            if len(tokens) >= 2:
                image = tokens[1]
                if len(tokens) >= 4 and tokens[2].upper() == "AS":
                    stages.add(tokens[3].lower())

                image_lower = image.lower()
                if image_lower in stages or image_lower == "scratch":
                    continue

                is_latest = image_lower.endswith(":latest")
                has_tag = ":" in image or "@" in image
                if is_latest or not has_tag:
                    findings.append(
                        Finding(
                            rule_id=rule.rule_id,
                            rule_name=rule.name,
                            severity=rule.severity,
                            category=rule.category,
                            cwe_id=rule.cwe_id,
                            cve=rule.cve,
                            cve_date=rule.cve_date,
                            file_path=target.display_path,
                            line_number=lineno,
                            column=1,
                            code_snippet=_snippet_text(line),
                            message=f"Unpinned base image '{image}' in FROM instruction; pin to an immutable tag or digest",
                            remediation=rule.remediation_example,
                        )
                    )

    return findings


def _analyze(target: SourceFile) -> list[Finding]:
    """Inspect one full-stack web or container file for security vulnerabilities."""
    rules = _rules_for(ANALYZER_NAME)
    if not rules:
        return []
    rulemap = {rule.rule_id: rule for rule in rules}

    findings: list[Finding] = []

    r_web001 = rulemap.get("WEB001")
    if r_web001:
        findings.extend(_check_dom_xss(target, r_web001))

    r_web002 = rulemap.get("WEB002")
    if r_web002:
        findings.extend(_check_secrets(target, r_web002))

    r_web003 = rulemap.get("WEB003")
    if r_web003:
        findings.extend(_check_php_rce(target, r_web003))

    r_web004 = rulemap.get("WEB004")
    if r_web004:
        findings.extend(_check_dockerfile_privilege(target, r_web004))

    r_web005 = rulemap.get("WEB005")
    if r_web005:
        findings.extend(_check_dockerfile_images(target, r_web005))

    return findings


def _name() -> str:
    """Return the analyzer identifier matching webfile.json."""
    return ANALYZER_NAME
