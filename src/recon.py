from __future__ import annotations
import concurrent.futures, socket, urllib.parse
from typing import Any

class ReconAuditor:
    def _default_ports(self) -> dict[int, str]:
        return {
            22: "SSH",
            80: "HTTP",
            443: "HTTPS",
            2375: "Docker Daemon API",
            3000: "Dev Web / Grafana",
            3306: "MySQL Database",
            5000: "Flask / Registry",
            5432: "PostgreSQL Database",
            6379: "Redis In-Memory Cache",
            8000: "Alternative HTTP / FastAPI",
            8080: "Alternative HTTP / Proxy",
            8443: "Alternative HTTPS",
            8888: "Jupyter / Admin UI",
            9000: "Portainer / SonarQube",
            9200: "Elasticsearch REST API",
            11211: "Memcached",
            27017: "MongoDB Database",
        }

    def _normalize_host(self, target: str) -> str:
        clean = target.strip()
        if "://" in clean:
            parsed = urllib.parse.urlparse(clean)
            return parsed.hostname or clean
        if ":" in clean:
            return clean.split(":", 1)[0]
        return clean

    def _probe_single_port(
        self,
        host: str,
        port: int,
        timeout: float = 1.2,
    ) -> tuple[bool, str]:
        try:
            with socket.create_connection((host, port), timeout=timeout) as s:
                s.settimeout(0.8)
                is_http = port in (80, 8080, 8000, 3000, 5000)
                probe_payload = b"HEAD / HTTP/1.0\r\n\r\n" if is_http else b"\r\n"
                try:
                    s.sendall(probe_payload)
                    banner = s.recv(128).decode("utf-8", errors="ignore").strip()
                    first_line = banner.splitlines()[0] if banner else ""
                    return True, first_line[:60]
                except Exception:
                    return True, ""
        except Exception:
            return False, ""

    def _scan_host(
        self,
        target: str,
        ports: list[int] | None = None,
        timeout: float = 1.2,
        concurrency: int = 10,
    ) -> tuple[int, list[dict[str, Any]], list[dict[str, Any]]]:
        host = self._normalize_host(target)
        port_dict = self._default_ports()
        test_ports = sorted(ports if ports else port_dict.keys())

        open_ports: list[dict[str, Any]] = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
            future_to_port = {
                pool.submit(self._probe_single_port, host, p, timeout): p
                for p in test_ports
            }
            for fut in concurrent.futures.as_completed(future_to_port):
                p = future_to_port[fut]
                is_open, banner = fut.result()
                if is_open:
                    service_name = port_dict.get(p, f"Port {p}")
                    open_ports.append(
                        {
                            "port": p,
                            "service": service_name,
                            "banner": banner,
                        }
                    )

        open_ports.sort(key=lambda x: x["port"])
        findings: list[dict[str, Any]] = []
        is_loopback = host in ("localhost", "127.0.0.1", "::1")

        db_ports = {2375, 3306, 5432, 6379, 9200, 11211, 27017}
        admin_ports = {3000, 5000, 8888, 9000}

        for item in open_ports:
            p = item["port"]
            svc = item["service"]

            if p in db_ports and not is_loopback:
                findings.append(
                    {
                        "rule_id": "REC001",
                        "severity": "CRITICAL",
                        "title": f"Exposed Database / Cache Service ({svc})",
                        "port": p,
                        "detail": f"{svc} is directly exposed on port {p} without firewall.",
                        "remediation": "Bind database strictly to localhost or private subnet.",
                    }
                )
            elif p in admin_ports and not is_loopback:
                findings.append(
                    {
                        "rule_id": "REC002",
                        "severity": "HIGH",
                        "title": f"Exposed Administrative / Dev Port ({svc})",
                        "port": p,
                        "detail": f"Internal service {svc} is exposed on external port {p}.",
                        "remediation": "Restrict admin ports via VPN or reverse proxy auth.",
                    }
                )
            elif p in (80, 8000, 8080) and not is_loopback:
                findings.append(
                    {
                        "rule_id": "REC003",
                        "severity": "MEDIUM",
                        "title": "Unencrypted Plaintext HTTP Port Open",
                        "port": p,
                        "detail": f"HTTP service listening unencrypted on port {p}.",
                        "remediation": "Redirect all plaintext traffic to HTTPS (port 443).",
                    }
                )

        return len(findings), findings, open_ports

    def _render_text(
        self,
        findings: list[dict[str, Any]],
        open_ports: list[dict[str, Any]],
        target: str,
    ) -> str:
        host = self._normalize_host(target)
        count_ports = len(self._default_ports())
        lines: list[str] = [
            f"Sentinel Port & Exposed Service Recon: {host}",
            f"Scanned {count_ports} critical service ports. Found {len(open_ports)} open:\n",
        ]

        if open_ports:
            lines.append("  Port    Service                        Banner")
            lines.append("  ------  -----------------------------  --------------------")
            for item in open_ports:
                p_str = f"{item['port']}/tcp"
                svc = item["service"]
                banner = item["banner"] or "-"
                lines.append(f"  {p_str:<6}  {svc:<29}  {banner[:34]}")
            lines.append("")

        if not findings:
            lines.append("Verdicts: [SAFE] No dangerous database or administrative ports exposed.")
            return "\n".join(lines)

        lines.append(f"Identified {len(findings)} exposed service vulnerability(ies):\n")
        for f in findings:
            lines.append(f"[{f['severity']}] {f['rule_id']} - {f['title']}")
            lines.append(f"  • Port: {f['port']}/tcp")
            lines.append(f"  • Detail: {f['detail']}")
            lines.append(f"  • Remediation: {f['remediation']}\n")
        return "\n".join(lines)

_auditor = ReconAuditor()

def _scan(
    target: str,
    ports: list[int] | None = None,
    timeout: float = 1.2,
) -> tuple[int, list[dict[str, Any]], list[dict[str, Any]]]:
    return _auditor._scan_host(target, ports=ports, timeout=timeout)

def _render(
    findings: list[dict[str, Any]],
    open_ports: list[dict[str, Any]],
    target: str,
) -> str:
    return _auditor._render_text(findings, open_ports, target)
