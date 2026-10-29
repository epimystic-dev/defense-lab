"""End-to-end tests over the shipped example fixtures."""

from __future__ import annotations

import os
import unittest

from tests import support  # noqa: F401
from tests.support import rule_ids

from composecheck.scanner import scan_file
from composecheck.types import FileKind, Options, Verdict


PKG_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXAMPLES = os.path.join(PKG_DIR, "examples")


class HealthyDockerfileFixtureTests(unittest.TestCase):
    def test_healthy_dockerfile_fixture_is_healthy(self):
        r = scan_file(
            os.path.join(EXAMPLES, "healthy_Dockerfile"), Options(),
            kind=FileKind.DOCKERFILE,
        )
        self.assertEqual(r.verdict, Verdict.HEALTHY, r.to_dict())
        self.assertEqual(r.findings, [])


class WeakDockerfileFixtureTests(unittest.TestCase):
    def test_weak_dockerfile_fixture_is_unhealthy(self):
        r = scan_file(
            os.path.join(EXAMPLES, "weak_Dockerfile"), Options(),
            kind=FileKind.DOCKERFILE,
        )
        self.assertEqual(r.verdict, Verdict.UNHEALTHY)

    def test_weak_dockerfile_fires_expected_rules(self):
        r = scan_file(
            os.path.join(EXAMPLES, "weak_Dockerfile"),
            Options(strict=True),
            kind=FileKind.DOCKERFILE,
        )
        ids = set(rule_ids(r.findings))
        expected = (
            "DKF-001", "DKF-002", "DKF-003", "DKF-004", "DKF-005",
            "DKF-006", "DKF-007", "DKF-008", "DKF-009", "DKF-010",
        )
        for rid in expected:
            self.assertIn(rid, ids, rid + " did not fire")


class HealthyComposeFixtureTests(unittest.TestCase):
    def test_healthy_compose_fixture_is_healthy(self):
        r = scan_file(
            os.path.join(EXAMPLES, "healthy_compose.yml"), Options(),
            kind=FileKind.COMPOSE,
        )
        self.assertEqual(r.verdict, Verdict.HEALTHY, r.to_dict())
        self.assertEqual(r.findings, [])


class WeakComposeFixtureTests(unittest.TestCase):
    def test_weak_compose_fixture_is_unhealthy(self):
        r = scan_file(
            os.path.join(EXAMPLES, "weak_compose.yml"), Options(),
            kind=FileKind.COMPOSE,
        )
        self.assertEqual(r.verdict, Verdict.UNHEALTHY)

    def test_weak_compose_fires_expected_rules(self):
        r = scan_file(
            os.path.join(EXAMPLES, "weak_compose.yml"),
            Options(strict=True),
            kind=FileKind.COMPOSE,
        )
        ids = set(rule_ids(r.findings))
        expected = (
            "DC-001", "DC-002", "DC-003", "DC-004", "DC-005",
            "DC-006", "DC-007", "DC-008", "DC-009", "DC-010",
        )
        for rid in expected:
            self.assertIn(rid, ids, rid + " did not fire")


if __name__ == "__main__":
    unittest.main()
