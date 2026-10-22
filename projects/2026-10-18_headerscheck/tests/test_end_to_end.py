"""End-to-end over the shipped example fixtures."""

from __future__ import annotations

import os
import unittest

from headerscheck.scanner import scan_file
from headerscheck.types import Options, Verdict

from tests.support import rule_ids


PKG_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXAMPLES = os.path.join(PKG_DIR, "examples")


class HealthyFixtureTests(unittest.TestCase):
    def test_healthy_is_healthy(self):
        r = scan_file(
            os.path.join(EXAMPLES, "healthy_response.http"),
            Options(assume_https=True),
        )
        self.assertEqual(r.verdict, Verdict.HEALTHY, r.to_dict())


class WeakFixtureTests(unittest.TestCase):
    def test_weak_is_unhealthy(self):
        r = scan_file(
            os.path.join(EXAMPLES, "weak_response.http"),
            Options(assume_https=True),
        )
        self.assertEqual(r.verdict, Verdict.UNHEALTHY)

    def test_weak_fires_expected_rules(self):
        r = scan_file(
            os.path.join(EXAMPLES, "weak_response.http"),
            Options(assume_https=True),
        )
        ids = set(rule_ids(r.findings))
        for expected in (
            "HDR-001", "HDR-005", "HDR-008", "HDR-009",
            "HDR-013", "HDR-014", "HDR-015", "HDR-016",
        ):
            self.assertIn(expected, ids, expected + " did not fire")


if __name__ == "__main__":
    unittest.main()
