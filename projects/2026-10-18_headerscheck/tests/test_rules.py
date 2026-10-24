"""Rule-level tests - one focused suite per rule in REGISTRY."""

from __future__ import annotations

import unittest

from headerscheck.rules import REGISTRY
from headerscheck.types import Options, Severity

from tests.support import rule_ids, scan_string


def http_response(headers_block: str, status_line: str = "HTTP/1.1 200 OK") -> str:
    return status_line + "\n" + headers_block + "\n"


HTTPS = Options(assume_https=True)
HTTP = Options(assume_https=False)


class Hdr001Tests(unittest.TestCase):
    def test_missing_hsts_on_https_fires(self):
        text = http_response("Content-Type: text/html\n")
        self.assertIn("HDR-001", rule_ids(scan_string(text, HTTPS)))

    def test_present_hsts_is_clean(self):
        text = http_response(
            "Content-Type: text/html\n"
            "Strict-Transport-Security: max-age=31536000\n"
        )
        self.assertNotIn("HDR-001", rule_ids(scan_string(text, HTTPS)))

    def test_http_does_not_fire(self):
        text = http_response("Content-Type: text/html\n")
        self.assertNotIn("HDR-001", rule_ids(scan_string(text, HTTP)))


class Hdr002Tests(unittest.TestCase):
    def test_short_max_age_fires(self):
        text = http_response(
            "Strict-Transport-Security: max-age=100\n"
            "Content-Type: text/html\n"
        )
        self.assertIn("HDR-002", rule_ids(scan_string(text, HTTPS)))

    def test_max_age_zero_fires_high(self):
        text = http_response(
            "Strict-Transport-Security: max-age=0\n"
            "Content-Type: text/html\n"
        )
        f = [x for x in scan_string(text, HTTPS) if x.rule_id == "HDR-002"]
        self.assertTrue(f)
        self.assertEqual(f[0].severity, Severity.HIGH)

    def test_long_max_age_is_clean(self):
        text = http_response(
            "Strict-Transport-Security: max-age=31536000\n"
            "Content-Type: text/html\n"
        )
        self.assertNotIn("HDR-002", rule_ids(scan_string(text, HTTPS)))

    def test_missing_max_age_fires(self):
        text = http_response(
            "Strict-Transport-Security: includeSubDomains\n"
            "Content-Type: text/html\n"
        )
        self.assertIn("HDR-002", rule_ids(scan_string(text, HTTPS)))

    def test_non_integer_max_age_fires(self):
        text = http_response(
            "Strict-Transport-Security: max-age=notanumber\n"
            "Content-Type: text/html\n"
        )
        self.assertIn("HDR-002", rule_ids(scan_string(text, HTTPS)))

    def test_negative_max_age_fires_high(self):
        # RFC 6797 section 6.1.1 requires a non-negative integer. A
        # negative value makes browsers reject the header entirely, so
        # the response ends up with no HSTS commit; that belongs with
        # max-age=0 at HIGH, not at MEDIUM alongside merely-short values.
        text = http_response(
            "Strict-Transport-Security: max-age=-100\n"
            "Content-Type: text/html\n"
        )
        f = [x for x in scan_string(text, HTTPS) if x.rule_id == "HDR-002"]
        self.assertTrue(f, "HDR-002 did not fire for negative max-age")
        self.assertEqual(f[0].severity, Severity.HIGH)
        self.assertIn("-100", f[0].message)


class Hdr003Tests(unittest.TestCase):
    def test_fires_only_under_include_info(self):
        text = http_response(
            "Strict-Transport-Security: max-age=31536000\n"
            "Content-Type: text/html\n"
        )
        default = rule_ids(scan_string(text, HTTPS))
        self.assertNotIn("HDR-003", default)
        opts = Options(assume_https=True, include_info=True)
        self.assertIn("HDR-003", rule_ids(scan_string(text, opts)))


class Hdr005Tests(unittest.TestCase):
    def test_missing_csp_on_html_fires(self):
        text = http_response(
            "Content-Type: text/html\n"
            "Strict-Transport-Security: max-age=31536000\n"
        )
        self.assertIn("HDR-005", rule_ids(scan_string(text, HTTPS)))

    def test_json_response_does_not_fire(self):
        text = http_response(
            "Content-Type: application/json\n"
            "Strict-Transport-Security: max-age=31536000\n"
        )
        self.assertNotIn("HDR-005", rule_ids(scan_string(text, HTTPS)))


class Hdr006Tests(unittest.TestCase):
    def test_unsafe_inline_fires(self):
        text = http_response(
            "Content-Type: text/html\n"
            "Strict-Transport-Security: max-age=31536000\n"
            "Content-Security-Policy: default-src 'self' 'unsafe-inline'\n"
        )
        f = [x for x in scan_string(text, HTTPS) if x.rule_id == "HDR-006"]
        self.assertTrue(f)
        self.assertEqual(f[0].severity, Severity.HIGH)

    def test_unsafe_eval_fires(self):
        text = http_response(
            "Content-Type: text/html\n"
            "Strict-Transport-Security: max-age=31536000\n"
            "Content-Security-Policy: default-src 'self'; script-src 'unsafe-eval'\n"
        )
        self.assertIn("HDR-006", rule_ids(scan_string(text, HTTPS)))

    def test_clean_csp_does_not_fire(self):
        text = http_response(
            "Content-Type: text/html\n"
            "Strict-Transport-Security: max-age=31536000\n"
            "Content-Security-Policy: default-src 'self'; frame-ancestors 'none'\n"
        )
        self.assertNotIn("HDR-006", rule_ids(scan_string(text, HTTPS)))


class Hdr007Tests(unittest.TestCase):
    def test_wildcard_fires(self):
        text = http_response(
            "Content-Type: text/html\n"
            "Strict-Transport-Security: max-age=31536000\n"
            "Content-Security-Policy: default-src 'self'; script-src *\n"
        )
        self.assertIn("HDR-007", rule_ids(scan_string(text, HTTPS)))

    def test_scheme_only_fires(self):
        text = http_response(
            "Content-Type: text/html\n"
            "Strict-Transport-Security: max-age=31536000\n"
            "Content-Security-Policy: default-src 'self'; script-src https:\n"
        )
        self.assertIn("HDR-007", rule_ids(scan_string(text, HTTPS)))

    def test_specific_host_is_clean(self):
        text = http_response(
            "Content-Type: text/html\n"
            "Strict-Transport-Security: max-age=31536000\n"
            "Content-Security-Policy: default-src 'self'; frame-ancestors 'none'; script-src 'self' https://cdn.example.test\n"
        )
        self.assertNotIn("HDR-007", rule_ids(scan_string(text, HTTPS)))


class Hdr008Tests(unittest.TestCase):
    def test_missing_fires(self):
        text = http_response("Content-Type: text/html\n")
        self.assertIn("HDR-008", rule_ids(scan_string(text, HTTPS)))

    def test_wrong_value_fires(self):
        text = http_response(
            "Content-Type: text/html\n"
            "X-Content-Type-Options: allow\n"
        )
        self.assertIn("HDR-008", rule_ids(scan_string(text, HTTPS)))

    def test_correct_value_is_clean(self):
        text = http_response(
            "Content-Type: text/html\n"
            "X-Content-Type-Options: nosniff\n"
            "Strict-Transport-Security: max-age=31536000\n"
            "Content-Security-Policy: default-src 'self'; frame-ancestors 'none'\n"
        )
        self.assertNotIn("HDR-008", rule_ids(scan_string(text, HTTPS)))


class Hdr009Tests(unittest.TestCase):
    def test_neither_fires(self):
        text = http_response(
            "Content-Type: text/html\n"
            "Strict-Transport-Security: max-age=31536000\n"
        )
        self.assertIn("HDR-009", rule_ids(scan_string(text, HTTPS)))

    def test_x_frame_options_satisfies(self):
        text = http_response(
            "Content-Type: text/html\n"
            "Strict-Transport-Security: max-age=31536000\n"
            "Content-Security-Policy: default-src 'self'\n"
            "X-Content-Type-Options: nosniff\n"
            "X-Frame-Options: DENY\n"
        )
        self.assertNotIn("HDR-009", rule_ids(scan_string(text, HTTPS)))

    def test_csp_frame_ancestors_satisfies(self):
        text = http_response(
            "Content-Type: text/html\n"
            "Strict-Transport-Security: max-age=31536000\n"
            "X-Content-Type-Options: nosniff\n"
            "Content-Security-Policy: default-src 'self'; frame-ancestors 'none'\n"
        )
        self.assertNotIn("HDR-009", rule_ids(scan_string(text, HTTPS)))


class Hdr010Tests(unittest.TestCase):
    """Referrer-Policy. Info-severity, so tests opt in with include_info.

    The W3C "parse a referrer policy from a Referrer-Policy header"
    algorithm walks a comma-separated list and keeps the LAST
    recognised token, so a weak fallback silently overrides a stronger
    primary - these tests pin that behaviour down.
    """

    OPTS = Options(assume_https=True, include_info=True)

    def _findings(self, text):
        return [f for f in scan_string(text, self.OPTS)
                if f.rule_id == "HDR-010"]

    def test_missing_fires(self):
        text = http_response("Content-Type: text/html\n")
        self.assertIn("HDR-010", rule_ids(scan_string(text, self.OPTS)))

    def test_strict_single_policy_is_clean(self):
        text = http_response(
            "Content-Type: text/html\n"
            "Referrer-Policy: strict-origin-when-cross-origin\n"
        )
        self.assertFalse(self._findings(text))

    def test_unsafe_url_single_policy_fires(self):
        text = http_response(
            "Content-Type: text/html\n"
            "Referrer-Policy: unsafe-url\n"
        )
        f = self._findings(text)
        self.assertTrue(f)
        self.assertIn("weak", f[0].message)

    def test_weak_fallback_after_strong_primary_fires(self):
        # Regression test for the W3C fallback-list parse. Without the
        # effective-policy walk, the whole value "strict-origin-when-
        # cross-origin, unsafe-url" is not in the weak set and the rule
        # reports clean - but browsers use the LAST recognised token
        # (unsafe-url), so the effective posture is weak.
        text = http_response(
            "Content-Type: text/html\n"
            "Referrer-Policy: strict-origin-when-cross-origin, unsafe-url\n"
        )
        f = self._findings(text)
        self.assertTrue(f, "weak fallback must be flagged")
        self.assertIn("unsafe-url", f[0].message)
        self.assertIn("last recognised token", f[0].message)

    def test_strong_fallback_after_unknown_primary_is_clean(self):
        # "foobar" is not a recognised policy token, so the algorithm
        # walks past it and settles on strict-origin-when-cross-origin.
        text = http_response(
            "Content-Type: text/html\n"
            "Referrer-Policy: foobar, strict-origin-when-cross-origin\n"
        )
        self.assertFalse(self._findings(text))

    def test_strong_primary_with_unknown_trailing_is_clean(self):
        # Unknown trailing tokens are ignored; the algorithm keeps the
        # last recognised value, which is the strong primary.
        text = http_response(
            "Content-Type: text/html\n"
            "Referrer-Policy: strict-origin-when-cross-origin, foobar\n"
        )
        self.assertFalse(self._findings(text))

    def test_all_tokens_unrecognised_fires(self):
        text = http_response(
            "Content-Type: text/html\n"
            "Referrer-Policy: foobar, bazbar\n"
        )
        f = self._findings(text)
        self.assertTrue(f)
        self.assertIn("no recognised policy token", f[0].message)

    def test_info_severity_hidden_by_default(self):
        text = http_response(
            "Content-Type: text/html\n"
            "Referrer-Policy: unsafe-url\n"
        )
        # HTTPS Options defaults have include_info=False, so HDR-010
        # (INFO) must not surface.
        self.assertNotIn("HDR-010", rule_ids(scan_string(text, HTTPS)))


class Hdr012Tests(unittest.TestCase):
    def test_versioned_server_fires_under_include_info(self):
        text = http_response(
            "Content-Type: application/json\n"
            "Server: nginx/1.18.0\n"
            "Strict-Transport-Security: max-age=31536000\n"
        )
        opts = Options(assume_https=True, include_info=True)
        self.assertIn("HDR-012", rule_ids(scan_string(text, opts)))

    def test_x_powered_by_fires(self):
        text = http_response(
            "Content-Type: application/json\n"
            "X-Powered-By: Express\n"
            "Strict-Transport-Security: max-age=31536000\n"
        )
        opts = Options(assume_https=True, include_info=True)
        self.assertIn("HDR-012", rule_ids(scan_string(text, opts)))

    def test_server_name_only_no_version_is_clean(self):
        text = http_response(
            "Content-Type: application/json\n"
            "Server: cloudflare\n"
            "Strict-Transport-Security: max-age=31536000\n"
        )
        opts = Options(assume_https=True, include_info=True)
        f = [x for x in scan_string(text, opts)
             if x.rule_id == "HDR-012" and x.header == "Server"]
        self.assertFalse(f)


class Hdr013Tests(unittest.TestCase):
    def test_cookie_without_secure_on_https_fires(self):
        text = http_response(
            "Content-Type: application/json\n"
            "Strict-Transport-Security: max-age=31536000\n"
            "Set-Cookie: sid=abc; HttpOnly; SameSite=Lax\n"
        )
        self.assertIn("HDR-013", rule_ids(scan_string(text, HTTPS)))

    def test_cookie_with_secure_is_clean(self):
        text = http_response(
            "Content-Type: application/json\n"
            "Strict-Transport-Security: max-age=31536000\n"
            "Set-Cookie: sid=abc; Secure; HttpOnly; SameSite=Lax\n"
        )
        self.assertNotIn("HDR-013", rule_ids(scan_string(text, HTTPS)))

    def test_http_does_not_fire(self):
        text = http_response(
            "Content-Type: application/json\n"
            "Set-Cookie: sid=abc; HttpOnly; SameSite=Lax\n"
        )
        self.assertNotIn("HDR-013", rule_ids(scan_string(text, HTTP)))


class Hdr014Tests(unittest.TestCase):
    def test_cookie_without_httponly_fires(self):
        text = http_response(
            "Content-Type: application/json\n"
            "Strict-Transport-Security: max-age=31536000\n"
            "Set-Cookie: sid=abc; Secure; SameSite=Lax\n"
        )
        self.assertIn("HDR-014", rule_ids(scan_string(text, HTTPS)))


class Hdr015Tests(unittest.TestCase):
    def test_cookie_without_samesite_fires(self):
        text = http_response(
            "Content-Type: application/json\n"
            "Strict-Transport-Security: max-age=31536000\n"
            "Set-Cookie: sid=abc; Secure; HttpOnly\n"
        )
        self.assertIn("HDR-015", rule_ids(scan_string(text, HTTPS)))


class Hdr016Tests(unittest.TestCase):
    def test_wildcard_plus_credentials_fires(self):
        text = http_response(
            "Content-Type: application/json\n"
            "Strict-Transport-Security: max-age=31536000\n"
            "Access-Control-Allow-Origin: *\n"
            "Access-Control-Allow-Credentials: true\n"
        )
        self.assertIn("HDR-016", rule_ids(scan_string(text, HTTPS)))

    def test_specific_origin_plus_credentials_is_clean(self):
        text = http_response(
            "Content-Type: application/json\n"
            "Strict-Transport-Security: max-age=31536000\n"
            "Access-Control-Allow-Origin: https://partner.example.test\n"
            "Access-Control-Allow-Credentials: true\n"
        )
        self.assertNotIn("HDR-016", rule_ids(scan_string(text, HTTPS)))


class RegistryIntegrityTests(unittest.TestCase):
    def test_rule_ids_are_unique(self):
        ids = [r.id for r in REGISTRY]
        self.assertEqual(len(ids), len(set(ids)))

    def test_first_rule_is_hdr_001(self):
        self.assertEqual(REGISTRY[0].id, "HDR-001")


class DisableAndOnlyTests(unittest.TestCase):
    def test_disable_suppresses(self):
        text = http_response(
            "Content-Type: text/html\n"
        )
        opts = Options(assume_https=True, disabled=("HDR-001",))
        self.assertNotIn("HDR-001", rule_ids(scan_string(text, opts)))

    def test_only_restricts(self):
        text = http_response(
            "Content-Type: text/html\n"
        )
        opts = Options(assume_https=True, only=("HDR-001",))
        self.assertEqual(set(rule_ids(scan_string(text, opts))), {"HDR-001"})


if __name__ == "__main__":
    unittest.main()
