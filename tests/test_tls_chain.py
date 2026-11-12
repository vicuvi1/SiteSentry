"""Regression tests: an unverifiable certificate chain must not be reported as an invalid certificate.

Found while scanning 100 popular sites: on Windows, sites using a root CA not yet cached
locally (e.g. some GlobalSign roots) were wrongly graded F.
"""
import ssl
import unittest

from sitesentry import scoring
from sitesentry.checks import tls
from sitesentry.models import Finding, Severity, Status
from sitesentry.net import is_chain_error, make_ssl_context


def verify_error(code: int, message: str) -> ssl.SSLCertVerificationError:
    exc = ssl.SSLCertVerificationError(1, message)
    exc.verify_code = code
    exc.verify_message = message
    return exc


class ChainClassificationTests(unittest.TestCase):
    def test_missing_issuer_is_a_chain_error(self):
        self.assertTrue(is_chain_error(verify_error(20, "unable to get local issuer certificate")))
        self.assertTrue(is_chain_error(verify_error(21, "unable to verify the first certificate")))

    def test_real_certificate_problems_are_not_chain_errors(self):
        for code, msg in [(10, "certificate has expired"), (62, "hostname mismatch"),
                          (18, "self-signed certificate"), (19, "self-signed certificate in certificate chain")]:
            with self.subTest(msg=msg):
                self.assertFalse(is_chain_error(verify_error(code, msg)))

    def test_chain_issue_is_a_warning_not_an_automatic_f(self):
        f = tls.chain_incomplete("unable to get local issuer certificate", have_ca_bundle=True)
        self.assertEqual((f.status, f.severity), (Status.WARN, Severity.MEDIUM))
        ok = Finding("x", "T", "t", Status.PASS, Severity.HIGH, "d")
        self.assertNotEqual(scoring.score([ok, f])[1], "F")
        self.assertEqual(scoring.score([ok, tls.certificate_invalid("expired")])[1], "F")

    def test_hint_shown_only_without_ca_bundle(self):
        self.assertIn("install 'certifi'", tls.chain_incomplete("x", have_ca_bundle=False).detail)
        self.assertNotIn("install 'certifi'", tls.chain_incomplete("x", have_ca_bundle=True).detail)


class ContextTests(unittest.TestCase):
    def test_contexts_enforce_tls12_minimum(self):
        for verify in (True, False):
            ctx = make_ssl_context(verify)
            self.assertGreaterEqual(ctx.minimum_version, ssl.TLSVersion.TLSv1_2)
        self.assertEqual(make_ssl_context(True).verify_mode, ssl.CERT_REQUIRED)


if __name__ == "__main__":
    unittest.main()
