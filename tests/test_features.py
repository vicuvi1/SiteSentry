"""Category scores, baseline diffs, bulk scanning and the live-progress (SSE) endpoint."""
import contextlib
import http.client
import io
import json
import os
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer

from test_scan import InsecureSite

from sitesentry import bulk, cli, diff, scoring
from sitesentry.models import Finding, ScanResult, Severity, Status
from sitesentry.web import RateLimiter, SiteSentryServer


def f(check_id, category, status, severity=Severity.MEDIUM, title=None):
    return Finding(check_id, category, title or check_id, status, severity, "d")


def start(server):
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


class CategoryScoreTests(unittest.TestCase):
    def test_weighted_share_with_half_credit_for_warnings(self):
        findings = [
            f("a", "Headers", Status.PASS, Severity.MEDIUM),   # 8 of 8
            f("b", "Headers", Status.WARN, Severity.MEDIUM),   # 4 of 8
            f("c", "Headers", Status.FAIL, Severity.LOW),      # 0 of 3
            f("d", "TLS", Status.PASS, Severity.HIGH),
            f("e", "Best practice", Status.FAIL, Severity.INFO),  # weight floor of 1
            f("g", "Cookies", Status.INFO, Severity.INFO),       # neutral, ignored
        ]
        self.assertEqual(scoring.category_scores(findings), {"Headers": 63, "TLS": 100, "Best practice": 0})

    def test_scan_result_json_includes_categories(self):
        r = ScanResult("t", "https://x.test/", "now", 0.1, [f("a", "TLS", Status.PASS)])
        self.assertEqual(r.to_dict()["categories"], {"TLS": 100})


class DiffTests(unittest.TestCase):
    def test_regressions_improvements_and_new_issues(self):
        baseline = {"score": 80, "grade": "B", "findings": [
            {"check_id": "headers.hsts", "status": "pass"},
            {"check_id": "headers.csp", "status": "fail"},
            {"check_id": "dns.caa", "status": "info"},
        ]}
        current = ScanResult("t", "u", "now", 0.1, [
            f("headers.hsts", "H", Status.FAIL, title="HSTS"),
            f("headers.csp", "H", Status.WARN, title="CSP"),
            f("dns.caa", "D", Status.FAIL, Severity.INFO, title="CAA"),   # info -> fail: neutral, not a regression
            f("cookies.secure", "C", Status.FAIL, title="Secure"),
        ])
        current.score, current.grade = 70, "B"
        d = diff.compare(baseline, current)
        self.assertEqual([c.check_id for c in d.regressions], ["headers.hsts"])
        self.assertEqual([c.check_id for c in d.improvements], ["headers.csp"])
        self.assertEqual([c.check_id for c in d.new_checks], ["cookies.secure"])
        self.assertTrue(d.has_regressions)
        text = diff.to_text(d)
        self.assertIn("80 -> 70 (-10)", text)
        self.assertIn("PASS -> FAIL  HSTS", text)


class BulkTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.servers = [start(ThreadingHTTPServer(("127.0.0.1", 0), InsecureSite)) for _ in range(2)]
        cls.urls = [f"http://127.0.0.1:{s.server_address[1]}/" for s in cls.servers]

    @classmethod
    def tearDownClass(cls):
        for s in cls.servers:
            s.shutdown()
            s.server_close()

    def write_list(self, text):
        fd, path = tempfile.mkstemp(suffix=".txt")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        self.addCleanup(os.remove, path)
        return path

    def test_read_targets_skips_comments_blanks_and_duplicates(self):
        path = self.write_list("# my sites\na.test\n\nb.test  # staging\na.test\n")
        self.assertEqual(bulk.read_targets(path), ["a.test", "b.test"])

    def test_read_targets_enforces_limit(self):
        path = self.write_list("\n".join(f"s{i}.test" for i in range(bulk.MAX_SITES + 1)))
        with self.assertRaises(ValueError):
            bulk.read_targets(path)

    def test_scan_many_keeps_order_and_reports_errors(self):
        items = bulk.scan_many([self.urls[0], "not a url", self.urls[1]], workers=3, timeout=3)
        self.assertEqual([i.target for i in items], [self.urls[0], "not a url", self.urls[1]])
        self.assertEqual(items[0].result.grade, "F")
        self.assertIsNone(items[1].result)
        self.assertIn("not a valid", items[1].error)
        csv_text = bulk.to_csv(items)
        self.assertEqual(csv_text.splitlines()[0].split(",")[:4], ["target", "final_url", "grade", "score"])
        self.assertIn("2/3 scanned", bulk.to_table(items))

    def test_cli_list_writes_csv_and_applies_fail_under(self):
        path = self.write_list("\n".join(self.urls))
        out_csv = path + ".csv"
        self.addCleanup(lambda: os.path.exists(out_csv) and os.remove(out_csv))
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            code = cli.main(["--list", path, "--csv", out_csv, "--fail-under", "C", "--timeout", "3"])
        self.assertEqual(code, 1)  # the insecure test sites score F
        with open(out_csv, encoding="utf-8") as fh:
            self.assertEqual(len(fh.read().strip().splitlines()), 3)

    def test_cli_baseline_fail_on_regression(self):
        fd, base = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump({"score": 100, "grade": "A+", "findings": [{"check_id": "headers.csp", "status": "pass"}]}, fh)
        self.addCleanup(os.remove, base)
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            code = cli.main([self.urls[0], "--baseline", base, "--fail-on-regression", "--timeout", "3", "--no-color"])
        self.assertEqual(code, 1)
        self.assertIn("Regressions:", out.getvalue())


class StreamTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.target = start(ThreadingHTTPServer(("127.0.0.1", 0), InsecureSite))
        cls.open_web = start(SiteSentryServer(("127.0.0.1", 0), timeout=3, allow_private=True, rate_limit=100))
        cls.guarded_web = start(SiteSentryServer(("127.0.0.1", 0), timeout=3, rate_limit=100))

    @classmethod
    def tearDownClass(cls):
        for s in (cls.target, cls.open_web, cls.guarded_web):
            s.shutdown()
            s.server_close()

    def events(self, server, query):
        conn = http.client.HTTPConnection("127.0.0.1", server.server_address[1], timeout=20)
        conn.request("GET", f"/api/scan/stream?{query}")
        resp = conn.getresponse()
        self.assertEqual(resp.getheader("Content-Type"), "text/event-stream; charset=utf-8")
        raw = resp.read().decode()
        conn.close()
        out = []
        for block in raw.strip().split("\n\n"):
            lines = dict(line.split(": ", 1) for line in block.splitlines())
            out.append((lines["event"], json.loads(lines["data"])))
        return out

    def test_stream_sends_steps_then_result(self):
        evs = self.events(self.open_web, f"url=http://127.0.0.1:{self.target.server_address[1]}/")
        names = [e for e, _ in evs]
        self.assertGreaterEqual(names.count("step"), 4)
        self.assertEqual(names[-1], "result")
        self.assertEqual(evs[-1][1]["grade"], "F")
        self.assertIn("categories", evs[-1][1])
        self.assertTrue(all("t" in d for e, d in evs if e == "step"))

    def test_stream_reports_blocked_target_as_fail_event(self):
        evs = self.events(self.guarded_web, f"url=http://127.0.0.1:{self.target.server_address[1]}/")
        self.assertEqual(evs[-1][0], "fail")
        self.assertEqual(evs[-1][1]["status"], 403)

    def test_stream_respects_rate_limit(self):
        self.guarded_web.limiter = RateLimiter(limit=1, window=60)
        try:
            self.events(self.guarded_web, "url=%20")
            evs = self.events(self.guarded_web, "url=%20")
            self.assertEqual((evs[-1][0], evs[-1][1]["status"]), ("fail", 429))
        finally:
            self.guarded_web.limiter = RateLimiter(limit=100)


class CompareTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.servers = [start(ThreadingHTTPServer(("127.0.0.1", 0), InsecureSite)) for _ in range(2)]

    @classmethod
    def tearDownClass(cls):
        for s in cls.servers:
            s.shutdown()
            s.server_close()

    def test_compare_report_cannot_break_out_of_script(self):
        from sitesentry import report
        evil = ScanResult("t", "https://x.test/</script><script>alert(1)</script>", "now", 0.1,
                          [Finding("x", "C", "</script>", Status.FAIL, Severity.LOW, "d")])
        html = report.to_compare_html(evil, evil)
        payload = html.split("window.__SITESENTRY_COMPARE__=")[1].split(";</script>")[0]
        self.assertNotIn("</script>", payload)
        self.assertNotIn("<", payload)

    def test_cli_compare_writes_report(self):
        urls = [f"http://127.0.0.1:{s.server_address[1]}/" for s in self.servers]
        fd, out_html = tempfile.mkstemp(suffix=".html")
        os.close(fd)
        self.addCleanup(os.remove, out_html)
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            code = cli.main(["--compare", *urls, "--html", out_html, "--timeout", "3"])
        self.assertEqual(code, 0)
        self.assertIn("SiteSentry comparison", out.getvalue())
        self.assertIn("Tie", out.getvalue())  # two identical insecure servers
        with open(out_html, encoding="utf-8") as fh:
            self.assertIn("window.__SITESENTRY_COMPARE__=", fh.read())


if __name__ == "__main__":
    unittest.main()
