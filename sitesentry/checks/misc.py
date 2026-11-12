"""security.txt (RFC 9116) and opt-in exposed-service port check."""
from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor

from ..models import Finding, Severity, Status
from ..net import HttpResponse

# port: (service, severity if open, why it matters)
RISKY_PORTS: dict[int, tuple[str, Severity, str]] = {
    21: ("FTP", Severity.HIGH, "sends credentials in plain text"),
    22: ("SSH", Severity.INFO, "normal for admin access; make sure password login is disabled"),
    23: ("Telnet", Severity.HIGH, "unencrypted remote shell"),
    445: ("SMB", Severity.HIGH, "file sharing, frequent ransomware entry point"),
    2375: ("Docker API", Severity.CRITICAL, "unauthenticated Docker API = full server takeover"),
    3306: ("MySQL", Severity.HIGH, "database should not be internet-facing"),
    3389: ("RDP", Severity.HIGH, "remote desktop, constantly brute-forced"),
    5432: ("PostgreSQL", Severity.HIGH, "database should not be internet-facing"),
    5900: ("VNC", Severity.HIGH, "remote desktop, often weakly protected"),
    6379: ("Redis", Severity.HIGH, "often has no authentication"),
    9200: ("Elasticsearch", Severity.HIGH, "common source of large data leaks"),
    11211: ("Memcached", Severity.HIGH, "abused for DDoS amplification"),
    27017: ("MongoDB", Severity.HIGH, "common source of large data leaks"),
}


def security_txt(resp: HttpResponse | None) -> Finding:
    title = "security.txt (vulnerability disclosure contact)"
    ref = "https://securitytxt.org/"
    if resp is not None and resp.status == 200 and b"contact:" in resp.body.lower():
        return Finding("misc.securitytxt", "Best practice", title, Status.PASS, Severity.INFO,
                       "A security contact is published, so researchers know where to report bugs.", reference=ref)
    return Finding("misc.securitytxt", "Best practice", title, Status.FAIL, Severity.INFO,
                   "No /.well-known/security.txt, so people who find a vulnerability have no official way to report it.",
                   "Publish /.well-known/security.txt with a Contact: line (generator at securitytxt.org).",
                   reference=ref)


def _is_open(host: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def port_findings(open_ports: list[int]) -> list[Finding]:
    if not open_ports:
        return [Finding("ports.exposed", "Exposed services", "Commonly abused ports", Status.PASS, Severity.HIGH,
                        f"None of the {len(RISKY_PORTS)} commonly abused service ports are reachable.",
                        evidence=", ".join(str(p) for p in sorted(RISKY_PORTS)))]
    out = []
    for port in sorted(open_ports):
        service, sev, why = RISKY_PORTS[port]
        status = Status.INFO if sev == Severity.INFO else Status.FAIL
        out.append(Finding(f"ports.{port}", "Exposed services", f"Port {port} ({service}) is open", status, sev,
                           f"{service} is reachable from the internet: {why}.",
                           "" if status == Status.INFO else "Close it with a firewall or restrict it to a VPN / allow-listed IPs.",
                           evidence=f"TCP {port} accepted a connection"))
    return out


def scan_ports(host: str, timeout: float = 1.5) -> list[Finding]:
    with ThreadPoolExecutor(max_workers=16) as pool:
        states = list(pool.map(lambda p: (p, _is_open(host, p, timeout)), RISKY_PORTS))
    return port_findings([p for p, is_open in states if is_open])
