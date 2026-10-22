"""Scanner-level tests."""

from __future__ import annotations

import os
import unittest

from headerscheck.scanner import scan_file, scan_paths, scan_text
from headerscheck.types import Options, Verdict

from tests.support import write_temp, rule_ids


HEALTHY = """HTTP/2 200
content-type: text/html; charset=utf-8
strict-transport-security: max-age=31536000; includeSubDomains
content-security-policy: default-src 'self'; frame-ancestors 'none'; script-src 'self'
x-content-type-options: nosniff
referrer-policy: strict-origin-when-cross-origin
"""

WEAK = """HTTP/1.1 200 OK
Server: nginx/1.18.0
X-Powered-By: PHP/7.4.3
Content-Type: text/html
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true
Set-Cookie: sid=abc

"""


class ScanTextTests(unittest.TestCase):
    def test_healthy_is_healthy(self):
        r = scan_text(HEALTHY, "healthy", Options(assume_https=True))
        self.assertEqual(r.verdict, Verdict.HEALTHY, r.to_dict())
        self.assertEqual(r.findings, [])
        self.assertEqual(r.responses_scanned, 1)

    def test_weak_is_unhealthy(self):
        r = scan_text(WEAK, "weak", Options(assume_https=True))
        self.assertEqual(r.verdict, Verdict.UNHEALTHY)
        self.assertIn("HDR-001", rule_ids(r.findings))


class ScanFileTests(unittest.TestCase):
    def test_round_trip(self):
        _d, p = write_temp(HEALTHY)
        try:
            r = scan_file(p, Options(assume_https=True))
            self.assertEqual(r.verdict, Verdict.HEALTHY)
        finally:
            os.remove(p)

    def test_missing_file_is_hdr_000(self):
        r = scan_file(
            os.path.join(os.path.dirname(__file__), "no-such"),
            Options())
        self.assertEqual(r.verdict, Verdict.UNHEALTHY)
        self.assertIn("HDR-000", rule_ids(r.findings))

    def test_unparseable_file_is_hdr_000(self):
        _d, p = write_temp("", name="empty.http")
        try:
            r = scan_file(p, Options(assume_https=True))
            self.assertIn("HDR-000", rule_ids(r.findings))
        finally:
            os.remove(p)


class ScanPathsTests(unittest.TestCase):
    def test_two_files_merge(self):
        d1, p1 = write_temp(HEALTHY, name="healthy_response.http")
        d2, p2 = write_temp(WEAK, name="weak_response.http")
        try:
            r = scan_paths([p1, p2], Options(assume_https=True))
            self.assertEqual(r.files_scanned, 2)
            self.assertEqual(r.verdict, Verdict.UNHEALTHY)
        finally:
            for p in (p1, p2):
                if os.path.exists(p):
                    os.remove(p)


if __name__ == "__main__":
    unittest.main()
