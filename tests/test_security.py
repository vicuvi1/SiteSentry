"""Attack-driven tests for SiteSentry's own defences: SSRF guard, IP pinning,
redirect checks, DNS-rebinding Host check, rate limiting."""
import http.client
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from sitesentry.net import request
from sitesentry.safety import BlockedTarget, TargetGuard, is_public_ip
from sitesentry.scanner import scan
from sitesentry.web import RateLimiter, SiteSentryServer


class Target(BaseHTTPRequestHandler):
    """/ serves a page; /redirect bounces to the cloud metadata service."""
    seen_hosts: list = []

    def log_message(self, *args):
        pass

    def do_GET(self):
        Target.seen_hosts.append(self.headers.get("Host"))
        if self.path.startswith("/redirect"):
            self.send_response(302)
            self.send_header("Location", "http://169.254.169.254/latest/meta-data/")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def start(server):
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


class PublicIpTests(unittest.TestCase):
    def test_internal_addresses_are_rejected(self):
        for ip in ["127.0.0.1", "10.0.0.5", "172.16.3.4", "192.168.1.1", "169.254.169.254", "100.64.0.1",
                   "0.0.0.0", "224.0.0.1", "::1", "fe80::1%3", "fc00::1", "::ffff:127.0.0.1",
                   "2002:7f00:1::1", "not-an-ip"]:
            with self.subTest(ip=ip):
                self.assertFalse(is_public_ip(ip))

    def test_public_addresses_are_allowed(self):
        for ip in ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"]:
            with self.subTest(ip=ip):
                self.assertTrue(is_public_ip(ip))


class GuardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = start(ThreadingHTTPServer(("127.0.0.1", 0), Target))
        cls.port = cls.server.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_guard_blocks_loopback_and_localhost(self):
        guard = TargetGuard()
        for host in ("127.0.0.1", "localhost"):
            with self.assertRaises(BlockedTarget):
                guard.resolve(host)

    def test_allow_private_disables_guard(self):
        self.assertIsNone(TargetGuard(allow_private=True).resolve("127.0.0.1"))

    def test_scan_of_internal_target_is_blocked(self):
        with self.assertRaises(BlockedTarget):
            scan(f"http://127.0.0.1:{self.port}/", guard=TargetGuard(), timeout=3)

    def test_redirect_into_metadata_service_is_blocked(self):
        # The first host is allowed (stands in for a public site), but its redirect
        # to 169.254.169.254 must be refused before any connection is made.
        guard = TargetGuard(allowed_hosts=("127.0.0.1",))
        with self.assertRaises(BlockedTarget) as ctx:
            scan(f"http://127.0.0.1:{self.port}/redirect", guard=guard, timeout=3, check_dns=False)
        self.assertIn("169.254.169.254", str(ctx.exception))

    def test_connection_is_pinned_to_vetted_ip(self):
        class PinGuard(TargetGuard):
            def resolve(self, host, port=None):
                return "127.0.0.1"  # vetted address, whatever DNS says later

        Target.seen_hosts.clear()
        resp = request(f"http://pinned.invalid:{self.port}/", guard=PinGuard(), timeout=3)
        self.assertEqual(resp.status, 200)
        self.assertEqual(Target.seen_hosts[-1], f"pinned.invalid:{self.port}")  # Host header kept


class RateLimiterTests(unittest.TestCase):
    def test_limit_per_client(self):
        rl = RateLimiter(limit=2, window=60)
        self.assertTrue(rl.allow("a"))
        self.assertTrue(rl.allow("a"))
        self.assertFalse(rl.allow("a"))
        self.assertTrue(rl.allow("b"))


class WebServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.target = start(ThreadingHTTPServer(("127.0.0.1", 0), Target))
        cls.web = start(SiteSentryServer(("127.0.0.1", 0), timeout=3, rate_limit=100))

    @classmethod
    def tearDownClass(cls):
        for s in (cls.target, cls.web):
            s.shutdown()
            s.server_close()

    def get(self, path, host=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.web.server_address[1], timeout=10)
        headers = {"Host": host} if host else {}
        conn.request("GET", path, headers=headers)
        resp = conn.getresponse()
        body = resp.read().decode()
        conn.close()
        return resp, body

    def test_ui_has_strict_csp_with_nonce(self):
        resp, body = self.get("/")
        csp = resp.getheader("Content-Security-Policy")
        nonce = csp.split("'nonce-")[1].split("'")[0]
        self.assertIn(f'<script nonce="{nonce}">', body)
        self.assertNotIn("unsafe-inline' ", csp.split("script-src")[1].split(";")[0])
        self.assertEqual(resp.getheader("X-Frame-Options"), "DENY")
        self.assertNotIn("Python", resp.getheader("Server"))

    def test_dns_rebinding_host_header_rejected(self):
        resp, _ = self.get("/", host="attacker.example")
        self.assertEqual(resp.status, 421)
        resp, _ = self.get("/", host=f"localhost:{self.web.server_address[1]}")
        self.assertEqual(resp.status, 200)

    def test_internal_scan_blocked_via_api(self):
        resp, body = self.get(f"/api/scan?url=http://127.0.0.1:{self.target.server_address[1]}/")
        self.assertEqual(resp.status, 403)
        self.assertIn("private or reserved", json.loads(body)["error"])

    def test_port_check_refused_in_shared_mode(self):
        self.web.local_only = False
        try:
            resp, _ = self.get("/api/scan?url=example.com&ports=1")
            self.assertEqual(resp.status, 403)
        finally:
            self.web.local_only = True

    def test_rate_limit(self):
        self.web.limiter = RateLimiter(limit=2, window=60)
        try:
            codes = [self.get("/api/scan?url=%20")[0].status for _ in range(3)]
            self.assertEqual(codes, [400, 400, 429])
        finally:
            self.web.limiter = RateLimiter(limit=100)


if __name__ == "__main__":
    unittest.main()
