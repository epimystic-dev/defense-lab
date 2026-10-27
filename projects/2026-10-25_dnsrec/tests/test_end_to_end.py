"""End-to-end tests over the shipped example fixtures."""

from __future__ import annotations

import os
import unittest

from tests import support  # noqa: F401
from tests.support import rule_ids

from dnsrec.scanner import scan_file
from dnsrec.types import Options, Verdict


PKG_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXAMPLES = os.path.join(PKG_DIR, "examples")


class HealthyFixtureTests(unittest.TestCase):
    def test_healthy_fixture_is_healthy(self):
        r = scan_file(
            os.path.join(EXAMPLES, "healthy_zone.txt"), Options())
        self.assertEqual(r.verdict, Verdict.HEALTHY, r.to_dict())
        self.assertEqual(r.findings, [])


class WeakFixtureTests(unittest.TestCase):
    def test_weak_fixture_is_unhealthy(self):
        r = scan_file(
            os.path.join(EXAMPLES, "weak_zone.txt"), Options())
        self.assertEqual(r.verdict, Verdict.UNHEALTHY)

    def test_weak_fixture_fires_expected_rules(self):
        r = scan_file(
            os.path.join(EXAMPLES, "weak_zone.txt"),
            Options(strict=True),
        )
        ids = set(rule_ids(r.findings))
        # Spot-check: every SPF / DMARC / DKIM rule the weak fixture is
        # shaped to catch.
        expected = (
            "SPF-001", "SPF-002", "SPF-003", "SPF-004", "SPF-005",
            "SPF-006", "SPF-007", "SPF-008", "SPF-009",
            "DMARC-001", "DMARC-002", "DMARC-003", "DMARC-004",
            "DMARC-005", "DMARC-006", "DMARC-007", "DMARC-008",
            "DMARC-009", "DMARC-010",
            "DKIM-001", "DKIM-002", "DKIM-003",
            "DKIM-005", "DKIM-006", "DKIM-007", "DKIM-008",
        )
        for rid in expected:
            self.assertIn(rid, ids, rid + " did not fire")


if __name__ == "__main__":
    unittest.main()
