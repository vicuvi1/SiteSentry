"""Unit tests for the individual checks (no network)."""
import unittest

from sitesentry.checks import content, cookies, cors, disclosure, headers, misc, tls, transport
from sitesentry.models import Severity, Status
from sitesentry.net import HttpResponse


def resp(url="https://site.test/", status=200, hdrs=None, body=b""):
    return HttpResponse(url, status, "OK", list((hdrs or {}).items()) if isinstance(hdrs, dict) else (hdrs or []), body)


class HeaderTests(unittest.TestCase):
    def test_hsts_missing_fails(self):
        self.assertEqual(headers.check_hsts(None).status, Status.FAIL)

    def test_hsts_short_max_age_warns(self):
        self.assertEqual(headers.check_hsts("max-age=300").status, Status.WARN)

    def test_hsts_good_passes(self):
        f = headers.check_hsts("max-age=31536000; includeSubDomains")
        self.assertEqual(f.status, Status.PASS)
        self.assertIn("includeSubDomains", f.detail)

    def test_csp_missing_and_report_only(self):
        self.assertEqual(headers.check_csp(None, None).status, Status.FAIL)
        self.assertIn("Report-Only", headers.check_csp(None, "default-src 'self'").detail)

    def test_csp_unsafe_inline_is_weak(self):
        f = headers.check_csp("default-src 'self'; script-src 'self' 'unsafe-inline'", None)
        self.assertEqual(f.status, Status.WARN)
        self.assertIn("unsafe-inline", f.detail)

    def test_csp_unsafe_inline_with_nonce_is_ok(self):
        f = headers.check_csp("script-src 'nonce-abc' 'unsafe-inline' 'strict-dynamic'", None)
        self.assertEqual(f.status, Status.PASS)

    def test_csp_wildcard_and_eval(self):
        issues = headers.csp_weaknesses("default-src * 'unsafe-eval'")
        self.assertEqual(len(issues), 2)

    def test_csp_without_script_restriction(self):
        self.assertTrue(headers.csp_weaknesses("img-src 'self'"))

    def test_clickjacking(self):
        self.assertEqual(headers.check_clickjacking("DENY", None).status, Status.PASS)
        self.assertEqual(headers.check_clickjacking("sameorigin", None).status, Status.PASS)
        self.assertEqual(headers.check_clickjacking(None, "frame-ancestors 'none'").status, Status.PASS)
        self.assertEqual(headers.check_clickjacking("ALLOW-FROM https://x", None).status, Status.WARN)
        self.assertEqual(headers.check_clickjacking(None, None).status, Status.FAIL)

    def test_referrer_policy_uses_last_value(self):
        self.assertEqual(headers.check_referrer_policy("unsafe-url, no-referrer").status, Status.PASS)
        self.assertEqual(headers.check_referrer_policy("no-referrer, unsafe-url").status, Status.WARN)

    def test_hsts_skipped_on_http(self):
        ids = [f.check_id for f in headers.run(resp(url="http://site.test/"))]
        self.assertNotIn("headers.hsts", ids)


class CookieTests(unittest.TestCase):
    def test_parse(self):
        c = cookies.parse_set_cookie("sid=abc; Path=/; Secure; HttpOnly; SameSite=Lax")
        self.assertEqual(c.name, "sid")
        self.assertTrue(c.secure and c.httponly)
        self.assertEqual(c.samesite, "lax")

    def test_insecure_cookie_flags(self):
        r = resp(hdrs=[("Set-Cookie", "sid=1; Path=/"), ("Set-Cookie", "ok=2; Secure; HttpOnly; SameSite=Strict")])
        by_id = {f.check_id: f for f in cookies.run([r])}
        self.assertEqual(by_id["cookies.secure"].status, Status.FAIL)
        self.assertEqual(by_id["cookies.secure"].evidence, "sid")
        self.assertEqual(by_id["cookies.httponly"].status, Status.WARN)
        self.assertEqual(by_id["cookies.samesite"].status, Status.WARN)

    def test_samesite_none_without_secure(self):
        f = {x.check_id: x for x in cookies.analyze([cookies.parse_set_cookie("a=1; SameSite=None")])}
        self.assertEqual(f["cookies.samesite"].severity, Severity.MEDIUM)

    def test_deletion_cookies_ignored(self):
        f = cookies.analyze([cookies.parse_set_cookie("old=; Max-Age=0")])
        self.assertEqual(f[0].check_id, "cookies.none")


class DisclosureTests(unittest.TestCase):
    def test_versioned_server_banner(self):
        f = disclosure.run([resp(hdrs={"Server": "Apache/2.4.41 (Ubuntu)", "X-Powered-By": "PHP/7.4.3"})])
        self.assertEqual([x.status for x in f], [Status.FAIL, Status.FAIL])

    def test_generic_server_ok(self):
        f = disclosure.run([resp(hdrs={"Server": "cloudflare"})])
        self.assertEqual([x.status for x in f], [Status.PASS, Status.PASS])


class ContentTests(unittest.TestCase):
    def test_active_mixed_content(self):
        html = b'<html><script src="http://cdn.test/a.js"></script><img src="https://ok.test/i.png"></html>'
        f = content.run(resp(hdrs={"Content-Type": "text/html"}, body=html))[0]
        self.assertEqual(f.status, Status.FAIL)

    def test_passive_mixed_content(self):
        html = b'<img src="http://cdn.test/i.png"><link rel="canonical" href="http://site.test/">'
        f = content.run(resp(hdrs={"Content-Type": "text/html"}, body=html))[0]
        self.assertEqual(f.status, Status.WARN)

    def test_not_checked_on_http(self):
        self.assertEqual(content.run(resp(url="http://x.test/", hdrs={"Content-Type": "text/html"})), [])


class CorsTests(unittest.TestCase):
    def test_reflected_origin_with_credentials(self):
        r = resp(hdrs={"Access-Control-Allow-Origin": cors.PROBE_ORIGIN, "Access-Control-Allow-Credentials": "true"})
        f = cors.check(r)
        self.assertEqual((f.status, f.severity), (Status.FAIL, Severity.HIGH))

    def test_wildcard_is_info(self):
        self.assertEqual(cors.check(resp(hdrs={"Access-Control-Allow-Origin": "*"})).status, Status.INFO)

    def test_no_cors(self):
        self.assertEqual(cors.check(resp()).status, Status.PASS)


class TransportTests(unittest.TestCase):
    def test_redirect_to_https(self):
        r = resp(url="http://site.test/", status=301, hdrs={"Location": "https://site.test/"})
        self.assertEqual(transport.http_redirect(r).status, Status.PASS)

    def test_relative_redirect_stays_http(self):
        r = resp(url="http://site.test/", status=302, hdrs={"Location": "/home"})
        self.assertEqual(transport.http_redirect(r).status, Status.FAIL)

    def test_http_closed(self):
        self.assertEqual(transport.http_redirect(None, "refused").status, Status.PASS)


class TlsTests(unittest.TestCase):
    def test_expiry_thresholds(self):
        self.assertEqual(tls.expiry_finding(-1, "CA", "x").severity, Severity.CRITICAL)
        self.assertEqual(tls.expiry_finding(5, "CA", "x").severity, Severity.HIGH)
        self.assertEqual(tls.expiry_finding(20, "CA", "x").status, Status.WARN)
        self.assertEqual(tls.expiry_finding(200, "CA", "x").status, Status.PASS)

    def test_protocols(self):
        self.assertEqual(tls.protocol_finding("TLSv1.3", "x").status, Status.PASS)
        self.assertEqual(tls.protocol_finding("TLSv1", "x").status, Status.FAIL)

    def test_legacy(self):
        self.assertEqual(tls.legacy_finding({"TLS 1.0": True, "TLS 1.1": False}).status, Status.FAIL)
        self.assertEqual(tls.legacy_finding({"TLS 1.0": False, "TLS 1.1": False}).status, Status.PASS)
        self.assertEqual(tls.legacy_finding({"TLS 1.0": None, "TLS 1.1": None}).status, Status.INFO)


class MiscTests(unittest.TestCase):
    def test_security_txt(self):
        ok = resp(body=b"Contact: mailto:security@site.test\n")
        self.assertEqual(misc.security_txt(ok).status, Status.PASS)
        self.assertEqual(misc.security_txt(resp(status=404)).status, Status.FAIL)
        self.assertEqual(misc.security_txt(None).severity, Severity.INFO)

    def test_ports(self):
        self.assertEqual(misc.port_findings([])[0].status, Status.PASS)
        found = {f.check_id: f for f in misc.port_findings([22, 6379])}
        self.assertEqual(found["ports.22"].status, Status.INFO)
        self.assertEqual(found["ports.6379"].status, Status.FAIL)


if __name__ == "__main__":
    unittest.main()
