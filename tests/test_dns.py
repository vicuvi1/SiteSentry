"""DNS packet encoding/decoding and the SPF / DMARC / CAA checks (no network)."""
import struct
import unittest

from sitesentry import dns
from sitesentry.checks import email_dns
from sitesentry.models import Severity, Status


def answer_packet(qid, name, answers, rcode=0):
    """Build a DNS response whose answers use a compression pointer to the question name."""
    header = struct.pack(">HHHHHH", qid, 0x8180 | rcode, 1, len(answers), 0, 0)
    question = dns.build_query(name, dns.TYPE_TXT, qid)[12:]
    body = b""
    for rtype, rdata in answers:
        body += b"\xc0\x0c" + struct.pack(">HHIH", rtype, 1, 300, len(rdata)) + rdata
    return header + question + body


def txt_rdata(*chunks):
    return b"".join(bytes([len(c)]) + c for c in chunks)


class PacketTests(unittest.TestCase):
    def test_build_query(self):
        q = dns.build_query("example.com", dns.TYPE_TXT, qid=0x1234)
        self.assertEqual(q[:2], b"\x12\x34")
        self.assertIn(b"\x07example\x03com\x00", q)
        self.assertEqual(q[-4:], b"\x00\x10\x00\x01")

    def test_rejects_bad_label(self):
        with self.assertRaises(dns.DNSError):
            dns.build_query("a" * 64 + ".com", dns.TYPE_TXT)

    def test_parse_split_txt_with_compression(self):
        msg = answer_packet(7, "example.com", [(dns.TYPE_TXT, txt_rdata(b"v=spf1 include:a.test ", b"-all"))])
        resp = dns.parse_response(msg, expected_id=7)
        self.assertEqual(resp.txt(), ["v=spf1 include:a.test -all"])

    def test_parse_caa_and_ignore_cname(self):
        caa = bytes([0, 5]) + b"issue" + b"letsencrypt.org"
        msg = answer_packet(9, "example.com", [(dns.TYPE_CNAME, b"\xc0\x0c"), (dns.TYPE_CAA, caa)])
        self.assertEqual(dns.parse_response(msg).caa(), [(0, "issue", "letsencrypt.org")])

    def test_id_mismatch_and_truncation(self):
        msg = answer_packet(1, "example.com", [])
        with self.assertRaises(dns.DNSError):
            dns.parse_response(msg, expected_id=2)
        with self.assertRaises(dns.DNSError):
            dns.parse_response(msg[:8])

    def test_nxdomain_rcode(self):
        self.assertEqual(dns.parse_response(answer_packet(3, "nope.test", [], rcode=3)).rcode, dns.RCODE_NXDOMAIN)


class SpfDmarcCaaTests(unittest.TestCase):
    def test_spf(self):
        self.assertEqual(email_dns.check_spf([]).status, Status.FAIL)
        self.assertEqual(email_dns.check_spf(["v=spf1 -all"]).status, Status.PASS)
        self.assertEqual(email_dns.check_spf(["v=spf1 include:x ~all"]).status, Status.PASS)
        self.assertEqual(email_dns.check_spf(["v=spf1 ?all"]).status, Status.WARN)
        self.assertEqual(email_dns.check_spf(["v=spf1 +all"]).severity, Severity.HIGH)
        self.assertEqual(email_dns.check_spf(["v=spf1 a mx"]).status, Status.WARN)
        self.assertEqual(email_dns.check_spf(["v=spf1 redirect=_spf.x.test"]).status, Status.PASS)
        self.assertEqual(email_dns.check_spf(["v=spf1 -all", "v=spf1 ~all"]).status, Status.FAIL)
        self.assertEqual(email_dns.check_spf(["google-site-verification=abc"]).status, Status.FAIL)

    def test_dmarc(self):
        self.assertEqual(email_dns.check_dmarc([], "x.test").status, Status.FAIL)
        self.assertEqual(email_dns.check_dmarc(["v=DMARC1; p=none"], "x.test").status, Status.WARN)
        self.assertEqual(email_dns.check_dmarc(["v=DMARC1; p=reject"], "x.test").status, Status.PASS)

    def test_caa(self):
        self.assertEqual(email_dns.check_caa([], None).status, Status.FAIL)
        self.assertEqual(email_dns.check_caa([], None).severity, Severity.INFO)
        self.assertEqual(email_dns.check_caa([(0, "issue", "pki.goog")], "x.test").status, Status.PASS)

    def test_org_domain(self):
        self.assertEqual(email_dns.org_domain("www.github.com"), "github.com")
        self.assertEqual(email_dns.org_domain("api.github.com"), "api.github.com")
        self.assertIsNone(email_dns.org_domain("127.0.0.1"))
        self.assertIsNone(email_dns.org_domain("localhost"))

    def test_run_with_fake_resolver_inherits_caa(self):
        zone = {
            ("shop.example.org", dns.TYPE_TXT): [(dns.TYPE_TXT, txt_rdata(b"v=spf1 -all"))],
            ("_dmarc.shop.example.org", dns.TYPE_TXT): [(dns.TYPE_TXT, txt_rdata(b"v=DMARC1; p=quarantine"))],
            ("example.org", dns.TYPE_CAA): [(dns.TYPE_CAA, bytes([0, 5]) + b"issueletsencrypt.org")],
        }

        def resolver(name, qtype):
            return dns.DNSResponse(0, zone.get((name, qtype), []))

        findings = {f.check_id: f for f in email_dns.run("shop.example.org", resolver=resolver)}
        self.assertEqual(findings["dns.spf"].status, Status.PASS)
        self.assertEqual(findings["dns.dmarc"].status, Status.PASS)
        self.assertEqual(findings["dns.caa"].status, Status.FAIL)  # parent not searched beyond org domain

        findings = {f.check_id: f for f in email_dns.run("www.example.org", resolver=resolver)}
        self.assertEqual(findings["dns.caa"].status, Status.PASS)  # www. -> example.org has CAA

    def test_lookup_failure_is_reported_not_raised(self):
        def broken(name, qtype):
            raise dns.DNSError("timed out")
        findings = email_dns.run("example.org", resolver=broken)
        self.assertEqual(findings[0].check_id, "dns.lookup")


if __name__ == "__main__":
    unittest.main()
