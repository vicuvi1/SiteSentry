"""SSRF protection for when SiteSentry runs as a shared web service.

A scanner that fetches arbitrary URLs is a textbook Server-Side Request
Forgery (SSRF) target: without protection, anyone who can reach the web UI
could make it probe the internal network (192.168.x.x, Redis on localhost, the
cloud metadata service at 169.254.169.254, ...).

TargetGuard resolves a hostname once, rejects it if ANY address is not
globally routable, and returns the vetted IP so the caller can connect to
exactly that address ("IP pinning"). Pinning closes the DNS-rebinding gap
where a hostname resolves to a public IP during the check and to a private
one a moment later during the real connection. The guard runs again on every
redirect hop, so a public site can't bounce the scanner to an internal address.
"""
from __future__ import annotations

import ipaddress
import socket

NAT64_WKP = ipaddress.ip_network("64:ff9b::/96")      # well-known NAT64 prefix: last 32 bits are IPv4
NAT64_LOCAL = ipaddress.ip_network("64:ff9b:1::/48")  # local-use NAT64
IPV4_COMPAT = ipaddress.ip_network("::/96")           # deprecated IPv4-compatible (::7f00:1)


class BlockedTarget(Exception):  # noqa: N818 - reads naturally at call sites
    """The target resolves to a private, loopback or otherwise reserved address."""


def is_public_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip.split("%", 1)[0])  # drop IPv6 zone id
    except ValueError:
        return False
    if isinstance(addr, ipaddress.IPv6Address):
        if addr.is_site_local or addr in NAT64_LOCAL:  # deprecated fec0::/10, local-use NAT64
            return False
        if addr.ipv4_mapped:  # ::ffff:127.0.0.1 is still loopback
            addr = addr.ipv4_mapped
        elif addr.sixtofour:  # 2002:7f00:1::/48 embeds 127.0.0.1
            addr = addr.sixtofour
        elif addr in NAT64_WKP or addr in IPV4_COMPAT:  # 64:ff9b::a9fe:a9fe = 169.254.169.254
            addr = ipaddress.IPv4Address(int(addr) & 0xFFFFFFFF)
    return addr.is_global and not addr.is_multicast


class TargetGuard:
    def __init__(self, *, allow_private: bool = False, allowed_hosts: tuple[str, ...] = ()):
        self.allow_private = allow_private
        self.allowed_hosts = {h.lower() for h in allowed_hosts}

    def resolve(self, host: str, port: int | None = None) -> str | None:
        """Return the IP to connect to, or None when no pinning is needed.

        Raises BlockedTarget for internal targets; socket errors (OSError)
        propagate so callers report them as normal network failures.
        """
        if self.allow_private:
            return None
        infos = socket.getaddrinfo(host, port or 443, type=socket.SOCK_STREAM)
        ips = list(dict.fromkeys(str(info[4][0]) for info in infos))
        if not ips:
            raise OSError(f"{host} did not resolve")
        if host.lower() not in self.allowed_hosts:
            blocked = [ip for ip in ips if not is_public_ip(ip)]
            if blocked:
                raise BlockedTarget(
                    f"{host} resolves to a private or reserved address ({blocked[0]}). "
                    "Scanning internal networks is blocked on this server."
                )
        return next((ip for ip in ips if ":" not in ip), ips[0])  # prefer IPv4
