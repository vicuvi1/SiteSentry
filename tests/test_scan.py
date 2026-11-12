"""Scoring, reports, CLI and an end-to-end scan against a local test server."""
import contextlib
import io
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from sitesentry import cli, report, scoring
from sitesentry.models import Finding, Severity, Status
from sitesentry.scanner import ScanError, normalize_target, scan


def finding(status, severity):
    return Finding("x", "Test", "t", status, severity, "d")


class ScoringTests(unittest.TestCase):
    def test_perfect(self):
        self.assertEqual(scoring.score([finding(Status.PASS, Severity.HIGH)]), (100, "A+"))

    def test_warn_costs_half(self):
        self.assertEqual(scoring.score([finding(Status.WARN, Severity.MEDIUM)])[0], 96)

    def test_critical_forces_f(self):
        self.assertEqual(scoring.score([finding(Status.FAIL, Severity.CRITICAL)]), (70, "F"))

    def test_floor_zero(self):
        self.assertEqual(scoring.score([finding(Status.FAIL, Severity.HIGH)] * 10)[0], 0)


class NormalizeTests(unittest.TestCase):
    def test_adds_scheme_and_path(self):
        self.assertEqual(normalize_target("example.com"), "https://example.com/")
        self.assertEqual(normalize_target(" http://a.test:8080/x?y=1 "), "http://a.test:8080/x?y=1")

    def test_rejects_garbage(self):
        for bad in ("", "ftp://x.test", "https://", "exa mple.com"):
            with self.assertRaises(ValueError):
                normalize_target(bad)


class InsecureSite(BaseHTTPRequestHandler):
    """A deliberately badly configured site."""

    def log_message(self, *args):
        pass

    def do_GET(self):
        if self.path == "/.well-known/security.txt":
            self.send_response(404)
            self.end_headers()
            return
        body = b"<html><body>hello</body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("X-Powered-By", "PHP/5.6.40")
        self.send_header("Set-Cookie", "PHPSESSID=abc123; path=/")
        origin = self.headers.get("Origin")
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class EndToEndTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), InsecureSite)
        cls.port = cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_scan_insecure_site(self):
        result = scan(f"http://127.0.0.1:{self.port}/", timeout=5)
        by_id = {f.check_id: f for f in result.findings}
        self.assertEqual(result.grade, "F")
        self.assertEqual(by_id["transport.https"].status, Status.FAIL)
        self.assertEqual(by_id["cors.origin"].severity, Severity.HIGH)
        self.assertEqual(by_id["cors.origin"].status, Status.FAIL)
        self.assertEqual(by_id["cookies.secure"].status, Status.FAIL)
        self.assertEqual(by_id["disclosure.tech"].status, Status.FAIL)
        self.assertEqual(by_id["headers.csp"].status, Status.FAIL)
        self.assertNotIn("headers.hsts", by_id)

    def test_reports_render(self):
        result = scan(f"http://127.0.0.1:{self.port}/", timeout=5)
        data = json.loads(report.to_json(result))
        self.assertEqual(data["grade"], "F")
        html = report.to_html(result)
        self.assertIn("window.__SITESENTRY_REPORT__=", html)
        self.assertNotIn(report.PLACEHOLDER, html.split("<script>window.__SITESENTRY_REPORT__")[0])
        self.assertIn("FAIL", report.to_console(result, color=False))

    def test_cli_json_and_fail_under(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = cli.main([f"127.0.0.1:{self.port}", "--json", "-", "--fail-under", "B", "--timeout", "5"])
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(out.getvalue())["grade"], "F")

    def test_unreachable_host(self):
        with self.assertRaises(ScanError):
            scan("http://127.0.0.1:1/", timeout=2)


class HtmlInjectionTests(unittest.TestCase):
    def test_report_cannot_break_out_of_script(self):
        from sitesentry.models import ScanResult
        r = ScanResult("t", "https://x.test/</script><script>alert(1)</script>", "now", 0.1,
                       [Finding("x", "C", "</script>", Status.FAIL, Severity.LOW, "d")])
        html = report.to_html(r)
        payload = html.split("window.__SITESENTRY_REPORT__=")[1].split(";</script>")[0]
        self.assertNotIn("</script>", payload)


if __name__ == "__main__":
    unittest.main()
