"""End-to-end tests over the shipped example fixtures."""

from __future__ import annotations

import os
import unittest

from sshdcheck.scanner import scan_file
from sshdcheck.types import Options, Verdict

from tests.support import rule_ids


PKG_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXAMPLES = os.path.join(PKG_DIR, "examples")


class HealthyFixtureTests(unittest.TestCase):
    def test_healthy_fixture_is_healthy(self):
        r = scan_file(
            os.path.join(EXAMPLES, "healthy_sshd_config"), Options())
        self.assertEqual(r.verdict, Verdict.HEALTHY, r.to_dict())
        self.assertEqual(r.findings, [])


class WeakFixtureTests(unittest.TestCase):
    def test_weak_fixture_is_unhealthy(self):
        r = scan_file(
            os.path.join(EXAMPLES, "weak_sshd_config"), Options())
        self.assertEqual(r.verdict, Verdict.UNHEALTHY)

    def test_weak_fixture_fires_expected_rules(self):
        r = scan_file(
            os.path.join(EXAMPLES, "weak_sshd_config"), Options())
        ids = set(rule_ids(r.findings))
        # Spot-check the rules a 'default-weak' sshd_config should trip.
        for expected in (
            "SSH-001", "SSH-002", "SSH-003", "SSH-004", "SSH-005",
            "SSH-006", "SSH-007", "SSH-008", "SSH-009", "SSH-010",
            "SSH-011", "SSH-012", "SSH-013", "SSH-015",
        ):
            self.assertIn(expected, ids, expected + " did not fire")


if __name__ == "__main__":
    unittest.main()
