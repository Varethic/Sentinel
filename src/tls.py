from __future__ import annotations
import datetime, socket, ssl, urllib.parse
from typing import Any

class TlsInspector:
    def _normalize_target(self, target: str) -> tuple[str, int]:
        clean = target.strip()
        if "://" in clean:
            parsed = urllib.parse.urlparse(clean)
            host = parsed.hostname or ""
            port = parsed.port or 443
            return host, port
        if ":" in clean:
            parts = clean.split(":", 1)
            return parts[0], int(parts[1]) if parts[1].isdigit() else 443
        return clean, 443

    def _get_cert_details(
        self,
        host: str,
        port: int,
        timeout: float = 6.0,
    ) -> tuple[dict[str, Any] | None, str | None, tuple[str, str, int] | None]:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.load_default_certs()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            with (
                socket.create_connection((host, port), timeout=timeout) as sock,
                ctx.wrap_socket(sock, server_hostname=host) as ssock,
            ):
                cert = ssock.getpeercert(binary_form=False)
                version = ssock.version()
                cipher = ssock.cipher()
                return cert, version, cipher
        except Exception:
            return None, None, None

    def _test_legacy_tls(self, host: str, port: int, timeout: float = 4.0) -> list[str]:
        deprecated: list[str] = []
        for name, proto in (
            ("TLSv1.0", getattr(ssl.TLSVersion, "TLSv1", None)),
            ("TLSv1.1", getattr(ssl.TLSVersion, "TLSv1_1", None)),
        ):
            if proto is None:
                continue
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            try:
                ctx.minimum_version = proto
                ctx.maximum_version = proto
                with (
                    socket.create_connection((host, port), timeout=timeout) as sock,
                    ctx.wrap_socket(sock, server_hostname=host) as ssock,
                ):
                    if ssock.version():
                        deprecated.append(name)
            except Exception:
                continue
        return deprecated

    def _audit(
        self,
        target: str,
        timeout: float = 6.0,
    ) -> tuple[int, list[dict[str, Any]], dict[str, Any]]:
        host, port = self._normalize_target(target)
        if not host:
            return 0, [], {"error": "Invalid host target"}

        cert, proto_version, cipher_tuple = self._get_cert_details(host, port, timeout=timeout)
        if not cert and not cipher_tuple:
            return 0, [], {"error": f"Could not establish TLS connection to {host}:{port}"}

        findings: list[dict[str, Any]] = []
        meta: dict[str, Any] = {
            "host": host,
            "port": port,
            "protocol": proto_version or "Unknown",
            "cipher": cipher_tuple[0] if cipher_tuple else "Unknown",
        }

        not_after = cert.get("notAfter", "") if cert else ""
        if not_after:
            try:
                fmt = "%b %d %H:%M:%S %Y %Z"
                expiry = datetime.datetime.strptime(not_after, fmt).replace(tzinfo=datetime.UTC)
                now = datetime.datetime.now(datetime.UTC)
                days_left = (expiry - now).days
                meta["days_until_expiry"] = days_left
                meta["expiry_date"] = expiry.strftime("%Y-%m-%d")

                if days_left < 0:
                    findings.append(
                        {
                            "rule_id": "TLS001",
                            "severity": "CRITICAL",
                            "title": "SSL/TLS Certificate Has Expired",
                            "detail": f"Expired {abs(days_left)} days ago ({meta['expiry_date']}).",
                            "remediation": "Renew and deploy a valid certificate immediately.",
                        }
                    )
                elif days_left < 30:
                    findings.append(
                        {
                            "rule_id": "TLS002",
                            "severity": "HIGH",
                            "title": "SSL/TLS Certificate Expiring Soon",
                            "detail": f"Expires in {days_left} day(s) on {meta['expiry_date']}.",
                            "remediation": "Automate certificate renewal before expiry.",
                        }
                    )
            except Exception:
                pass

        if cert:
            subject_dict = dict(x[0] for x in cert.get("subject", ()))
            issuer_dict = dict(x[0] for x in cert.get("issuer", ()))
            meta["subject_cn"] = subject_dict.get("commonName", "")
            meta["issuer_org"] = issuer_dict.get("organizationName", "")

            if subject_dict == issuer_dict and subject_dict:
                findings.append(
                    {
                        "rule_id": "TLS004",
                        "severity": "HIGH",
                        "title": "Self-Signed Certificate In Use",
                        "detail": f"Self-signed by {meta['issuer_org'] or meta['subject_cn']}.",
                        "remediation": "Use trusted CA authority (Let's Encrypt / DigiCert).",
                    }
                )

            sans: list[str] = [alt[1] for alt in cert.get("subjectAltName", ()) if alt[0] == "DNS"]
            meta["sans"] = sans
            if sans:
                matched_san = any(
                    host == san or (san.startswith("*.") and host.endswith(san[1:]))
                    for san in sans
                )
                if not matched_san and host != meta["subject_cn"]:
                    findings.append(
                        {
                            "rule_id": "TLS003",
                            "severity": "HIGH",
                            "title": "Hostname Not Covered in Certificate SAN",
                            "detail": f"Host '{host}' not in SANs ({', '.join(sans[:3])}).",
                            "remediation": "Reissue certificate including domain name in SAN.",
                        }
                    )

        legacy = self._test_legacy_tls(host, port, timeout=timeout)
        if legacy:
            findings.append(
                {
                    "rule_id": "TLS010",
                    "severity": "HIGH",
                    "title": "Deprecated TLS Protocol Version Supported",
                    "detail": f"Server accepts insecure protocol(s): {', '.join(legacy)}.",
                    "remediation": "Disable TLS 1.0 and 1.1; enforce TLS 1.2 and 1.3 only.",
                }
            )

        if cipher_tuple:
            cipher_name = cipher_tuple[0].upper()
            weak_algos = ("RC4", "3DES", "DES", "MD5", "_CBC_", "NULL", "EXPORT")
            if any(w in cipher_name for w in weak_algos):
                findings.append(
                    {
                        "rule_id": "TLS020",
                        "severity": "HIGH",
                        "title": "Weak or Deprecated Cipher Suite",
                        "detail": f"Cipher suite {cipher_name} contains insecure primitives.",
                        "remediation": "Configure modern AEAD cipher suites (e.g. AES-GCM).",
                    }
                )

            pfs_keywords = ("ECDHE", "DHE", "CHACHA20", "AES_128_GCM", "AES_256_GCM")
            if not any(k in cipher_name for k in pfs_keywords):
                findings.append(
                    {
                        "rule_id": "TLS021",
                        "severity": "MEDIUM",
                        "title": "Missing Perfect Forward Secrecy (PFS)",
                        "detail": f"Cipher {cipher_name} lacks ephemeral key exchange.",
                        "remediation": "Enable ECDHE key exchange cipher suites for PFS.",
                    }
                )

        return len(findings), findings, meta

    def _render_text(
        self,
        findings: list[dict[str, Any]],
        meta: dict[str, Any],
        target: str,
    ) -> str:
        if "error" in meta:
            return f"Sentinel TLS: {meta['error']}"

        lines: list[str] = [
            f"Sentinel TLS & Certificate Inspection: {meta['host']}:{meta['port']}",
            f"  • Protocol: {meta.get('protocol')} | Cipher: {meta.get('cipher')}",
            f"  • Issuer: {meta.get('issuer_org') or 'N/A'}",
            f"  • Subject: {meta.get('subject_cn') or 'N/A'}",
        ]
        if "days_until_expiry" in meta:
            rem = meta["days_until_expiry"]
            lines.append(f"  • Expiration: {meta['expiry_date']} ({rem} days remaining)")
        lines.append("")

        if not findings:
            lines.append("Verdicts: [SAFE] Certificate and TLS follow modern standards.")
            return "\n".join(lines)

        lines.append(f"Identified {len(findings)} SSL/TLS security gap(s):\n")
        for f in findings:
            lines.append(f"[{f['severity']}] {f['rule_id']} - {f['title']}")
            lines.append(f"  • Detail: {f['detail']}")
            lines.append(f"  • Remediation: {f['remediation']}\n")
        return "\n".join(lines)

_inspector = TlsInspector()

def _audit(
    target: str,
    timeout: float = 6.0,
) -> tuple[int, list[dict[str, Any]], dict[str, Any]]:
    return _inspector._audit(target, timeout=timeout)

def _render(
    findings: list[dict[str, Any]],
    meta: dict[str, Any],
    target: str,
) -> str:
    return _inspector._render_text(findings, meta, target)
