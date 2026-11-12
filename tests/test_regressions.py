"""Regression tests for bugs found in the v1.3.0 code review. Each test reproduces the original bug."""
import contextlib
import http.client
import io
import json
import os
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock

from sitesentry import cli, scanner
from sitesentry.net import FetchError, fetch_chain, request
from sitesentry.safety import is_public_ip
from sitesentry.web import SiteSentryServer


class Tricky(BaseHTTPRequestHandler):
    """Redirects that used to break the scanner, plus a redirected security.txt."""
    seen_paths: list = []

    def log_message(self, *args):
        pass

    def _send(self, status, body=b"", headers=()):
        self.send_response(status)
        for k, v in headers:
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        Tricky.seen_paths.append(self.path)
        if self.path == "/dead-redirect":
            self._send(302, headers=[("Location", "http://127.0.0.1:1/")])  # nothing listens on port 1
        elif self.path == "/unicode-redirect":
            self._send(302, headers=[("Location", "/café menu")])  # non-ASCII and a space
        elif self.path == "/.well-known/security.txt":
            self._send(301, headers=[("Location", "/security.txt")])
        elif self.path == "/security.txt":
            self._send(200, b"Contact: mailto:security@example.test\n", [("Content-Type", "text/plain")])
        else:
            self._send(200, b"<html>ok</html>", [("Content-Type", "text/html")])


def start(server):
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


class RedirectTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = start(ThreadingHTTPServer(("127.0.0.1", 0), Tricky))
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_failed_later_hop_keeps_partial_chain(self):
        # Bug 1: a dead redirect target was reported as "HTTPS unavailable" (forced F).
        notes: list[str] = []
        chain = fetch_chain(self.base + "/dead-redirect", timeout=3, notes=notes)
        self.assertEqual([r.status for r in chain], [302])
        self.assertIn("could not be followed", notes[0])

    def test_first_hop_failure_still_raises(self):
        with self.assertRaises(FetchError):
            fetch_chain("http://127.0.0.1:1/", timeout=3)

    def test_non_ascii_redirect_is_percent_encoded(self):
        # Bug 2: UnicodeEncodeError escaped and aborted the whole scan.
        chain = fetch_chain(self.base + "/unicode-redirect", timeout=3)
        self.assertEqual([r.status for r in chain], [302, 200])
        self.assertIn("/caf%C3%A9%20menu", Tricky.seen_paths)

    def test_security_txt_redirect_is_followed(self):
        # Bug 14: RFC 9116 allows redirects; a 301 used to count as "missing".
        result = scanner.scan(self.base + "/", timeout=3, check_dns=False)
        status = {f.check_id: f.status.value for f in result.findings}["misc.securitytxt"]
        self.assertEqual(status, "pass")


class PortTests(unittest.TestCase):
    def urls_tried(self, target):
        tried = []

        def fake_chain(url, **kw):
            tried.append(url)
            raise FetchError("offline")
        with mock.patch.object(scanner, "fetch_chain", fake_chain), self.assertRaises(scanner.ScanError):
            scanner.scan(target, check_dns=False)
        return tried

    def test_explicit_https_port_does_not_leak_to_http(self):
        # Bug 3: https://host:8443 made the HTTP probe hit the TLS port.
        self.assertEqual(self.urls_tried("https://example.test:8443/"),
                         ["https://example.test:8443/", "http://example.test/"])

    def test_explicit_http_port_does_not_leak_to_https(self):
        self.assertEqual(self.urls_tried("http://example.test:8080/x"),
                         ["https://example.test/x", "http://example.test:8080/x"])

    def test_port_without_scheme_is_used_for_both(self):
        self.assertEqual(self.urls_tried("example.test:8080"),
                         ["https://example.test:8080/", "http://example.test:8080/"])

    def test_ipv6_literal_keeps_brackets(self):
        self.assertEqual(self.urls_tried("https://[2001:db8::1]:8443/")[1], "http://[2001:db8::1]/")


class SsrfIpv6Tests(unittest.TestCase):
    def test_embedded_ipv4_forms_are_blocked(self):
        # Bug 12: NAT64 / IPv4-compatible / site-local addresses slipped through.
        for ip in ["64:ff9b::a9fe:a9fe", "64:ff9b::7f00:1", "::7f00:1", "fec0::1", "64:ff9b:1::1"]:
            with self.subTest(ip=ip):
                self.assertFalse(is_public_ip(ip))

    def test_nat64_of_public_ip_is_allowed(self):
        self.assertTrue(is_public_ip("64:ff9b::808:808"))  # NAT64 form of 8.8.8.8


class WebServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.web = start(SiteSentryServer(("127.0.0.1", 0), timeout=3, rate_limit=100))
        cls.port = cls.web.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.web.shutdown()
        cls.web.server_close()

    def get(self, path, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        conn.request("GET", path, headers=headers or {})
        resp = conn.getresponse()
        resp.read()
        conn.close()
        return resp

    def test_cross_site_requests_are_rejected(self):
        # Bug 5 (CSRF): any website could make a visitor's local server run scans.
        for headers in ({"Origin": "https://evil.example"}, {"Sec-Fetch-Site": "cross-site"},
                        {"Origin": "null"}):
            for path in ("/api/scan?url=example.com", "/api/scan/stream?url=example.com"):
                with self.subTest(headers=headers, path=path):
                    self.assertEqual(self.get(path, headers).status, 403)

    def test_same_origin_and_non_browser_requests_are_allowed(self):
        same = {"Origin": f"http://127.0.0.1:{self.port}", "Sec-Fetch-Site": "same-origin"}
        self.assertEqual(self.get("/api/scan?url=%20", same).status, 400)  # reaches validation
        self.assertEqual(self.get("/api/scan?url=%20").status, 400)  # curl / scripts

    def test_server_header_has_no_trailing_space_or_python_version(self):
        self.assertEqual(self.get("/").getheader("Server"), "SiteSentry")


class CliTests(unittest.TestCase):
    def tmp(self, text, suffix):
        fd, path = tempfile.mkstemp(suffix=suffix)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        self.addCleanup(os.remove, path)
        return path

    def run_cli(self, *args):
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()) as err:
            code = cli.main(list(args))
        return code, err.getvalue()

    def test_baseline_with_wrong_shape_is_a_clean_error(self):
        # Bug 7: a --list/--compare JSON file crashed with a traceback and exit code 1.
        path = self.tmp(json.dumps([{"target": "a"}]), ".json")
        code, err = self.run_cli("example.test", "--baseline", path)
        self.assertEqual(code, 2)
        self.assertIn("single-site report", err)

    def test_list_with_unreachable_sites_does_not_pass(self):
        # Bug 8: --list --fail-under exited 0 when every site failed to scan.
        path = self.tmp("http://127.0.0.1:1/\nhttp://127.0.0.1:2/\n", ".txt")
        code, err = self.run_cli("--list", path, "--fail-under", "B", "--no-dns", "--timeout", "2")
        self.assertEqual(code, 2)
        self.assertIn("could not be scanned", err)


class RequestTests(unittest.TestCase):
    def test_bad_characters_become_fetch_error_not_crash(self):
        with self.assertRaises(FetchError):
            request("http://127.0.0.1:1/é", timeout=1)


if __name__ == "__main__":
    unittest.main()
