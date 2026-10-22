"""In-process CLI tests."""

from __future__ import annotations

import json
import os
import unittest

from tests.support import run_cli, write_temp


HEALTHY = """HTTP/2 200
content-type: text/html; charset=utf-8
strict-transport-security: max-age=31536000; includeSubDomains
content-security-policy: default-src 'self'; frame-ancestors 'none'; script-src 'self'
x-content-type-options: nosniff
referrer-policy: strict-origin-when-cross-origin
"""


WEAK = """HTTP/1.1 200 OK
Content-Type: text/html
"""


class JsonAndTextTests(unittest.TestCase):
    def setUp(self):
        self._d, self._weak = write_temp(WEAK)
        self._d2, self._healthy = write_temp(HEALTHY, name="healthy.http")

    def tearDown(self):
        for p in (self._weak, self._healthy):
            if os.path.exists(p):
                os.remove(p)

    def test_text_output_prints_rule_ids(self):
        rc, out, _ = run_cli(["--assume-https", self._weak])
        self.assertNotEqual(rc, 0)
        self.assertIn("HDR-001", out)

    def test_json_output_parses(self):
        rc, out, _ = run_cli(
            ["--assume-https", "--json", self._weak])
        self.assertNotEqual(rc, 0)
        parsed = json.loads(out)
        self.assertEqual(parsed["verdict"], "unhealthy")

    def test_healthy_is_rc_zero(self):
        rc, _, _ = run_cli(["--assume-https", self._healthy])
        self.assertEqual(rc, 0)

    def test_assume_http_quietens_hsts_rules(self):
        rc, out, _ = run_cli(["--assume-http", self._weak])
        # HDR-001 should NOT appear on HTTP captures.
        self.assertNotIn("HDR-001", out)


class StrictModeTests(unittest.TestCase):
    def test_strict_promotes_info(self):
        text = (
            "HTTP/1.1 200 OK\n"
            "Content-Type: text/html\n"
            "Strict-Transport-Security: max-age=31536000; includeSubDomains\n"
            "Content-Security-Policy: default-src 'self'; frame-ancestors 'none'; script-src 'self'\n"
            "X-Content-Type-Options: nosniff\n"
            "Referrer-Policy: strict-origin-when-cross-origin\n"
        )
        d, p = write_temp(text)
        try:
            rc, out, _ = run_cli(
                ["--strict", "--assume-https", p])
            # Permissions-Policy (HDR-011) is INFO; strict promotes.
            self.assertNotEqual(rc, 0)
            self.assertIn("HDR-011", out)
        finally:
            os.remove(p)


if __name__ == "__main__":
    unittest.main()
