"""A tiny DNS client written from scratch (RFC 1035), stdlib only.

Python's standard library can resolve A/AAAA records but not TXT or CAA,
which we need for SPF, DMARC and CAA checks. So we build the query packet
ourselves, send it over UDP, fall back to TCP when the answer is truncated,
and parse the binary response, including name compression pointers.
"""
from __future__ import annotations

import random
import socket
import struct
from dataclasses import dataclass, field

TYPE_CNAME = 5
TYPE_TXT = 16
TYPE_CAA = 257
RCODE_NXDOMAIN = 3
DEFAULT_SERVERS = ("1.1.1.1", "8.8.8.8")


class DNSError(Exception):
    pass


@dataclass
class DNSResponse:
    rcode: int
    answers: list[tuple[int, bytes]] = field(default_factory=list)  # (type, rdata)
    message: bytes = b""

    def txt(self) -> list[str]:
        return [parse_txt(rdata) for rtype, rdata in self.answers if rtype == TYPE_TXT]

    def caa(self) -> list[tuple[int, str, str]]:
        return [parse_caa(rdata) for rtype, rdata in self.answers if rtype == TYPE_CAA]


def build_query(name: str, qtype: int, qid: int | None = None) -> bytes:
    qid = random.randint(0, 0xFFFF) if qid is None else qid
    header = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)  # RD flag, 1 question
    qname = b""
    for label in name.strip(".").split("."):
        try:
            raw = label.encode("idna")
        except UnicodeError as exc:
            raise DNSError(f"Invalid DNS label in {name!r}") from exc
        if not 0 < len(raw) < 64:
            raise DNSError(f"Invalid DNS label in {name!r}")
        qname += bytes([len(raw)]) + raw
    return header + qname + b"\x00" + struct.pack(">HH", qtype, 1)


def skip_name(msg: bytes, offset: int) -> int:
    """Return the offset just after a (possibly compressed) domain name."""
    while True:
        if offset >= len(msg):
            raise DNSError("Truncated name")
        length = msg[offset]
        if length == 0:
            return offset + 1
        if length & 0xC0 == 0xC0:  # compression pointer: 2 bytes, ends the name
            return offset + 2
        offset += 1 + length


def parse_response(msg: bytes, expected_id: int | None = None) -> DNSResponse:
    if len(msg) < 12:
        raise DNSError("Response too short")
    qid, flags, qdcount, ancount, _ns, _ar = struct.unpack(">HHHHHH", msg[:12])
    if expected_id is not None and qid != expected_id:
        raise DNSError("Response ID mismatch")
    offset = 12
    for _ in range(qdcount):
        offset = skip_name(msg, offset) + 4
    answers = []
    for _ in range(ancount):
        offset = skip_name(msg, offset)
        if offset + 10 > len(msg):
            raise DNSError("Truncated answer")
        rtype, _cls, _ttl, rdlength = struct.unpack(">HHIH", msg[offset:offset + 10])
        offset += 10
        answers.append((rtype, msg[offset:offset + rdlength]))
        offset += rdlength
    return DNSResponse(rcode=flags & 0x000F, answers=answers, message=msg)


def parse_txt(rdata: bytes) -> str:
    """TXT rdata is one or more <length><bytes> strings; SPF splits long records."""
    parts, i = [], 0
    while i < len(rdata):
        n = rdata[i]
        parts.append(rdata[i + 1:i + 1 + n].decode("utf-8", errors="replace"))
        i += 1 + n
    return "".join(parts)


def parse_caa(rdata: bytes) -> tuple[int, str, str]:
    flags, tag_len = rdata[0], rdata[1]
    tag = rdata[2:2 + tag_len].decode("ascii", errors="replace").lower()
    value = rdata[2 + tag_len:].decode("utf-8", errors="replace")
    return flags, tag, value


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise DNSError("Connection closed")
        data += chunk
    return data


def _ask(server: str, packet: bytes, timeout: float) -> bytes:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
        udp.settimeout(timeout)
        udp.sendto(packet, (server, 53))
        reply, _ = udp.recvfrom(4096)
    if struct.unpack(">H", reply[2:4])[0] & 0x0200:  # TC bit: retry over TCP
        with socket.create_connection((server, 53), timeout=timeout) as tcp:
            tcp.sendall(struct.pack(">H", len(packet)) + packet)
            length = struct.unpack(">H", _recv_exact(tcp, 2))[0]
            reply = _recv_exact(tcp, length)
    return reply


def query(name: str, qtype: int, *, timeout: float = 3.0, servers=DEFAULT_SERVERS) -> DNSResponse:
    last: Exception | None = None
    for server in servers:
        qid = random.randint(0, 0xFFFF)
        packet = build_query(name, qtype, qid)
        try:
            resp = parse_response(_ask(server, packet, timeout), expected_id=qid)
            if resp.rcode not in (0, RCODE_NXDOMAIN):  # SERVFAIL, REFUSED... aren't answers
                raise DNSError(f"{server} returned DNS error code {resp.rcode}")
            return resp
        except (OSError, DNSError, struct.error, IndexError) as exc:
            last = exc
    raise DNSError(f"DNS lookup for {name} failed: {last}")
