"""Verdict rollup tests."""

from __future__ import annotations

import unittest

from tests import support  # noqa: F401

from composecheck.types import Finding, Options, Severity, Verdict
from composecheck.verdict import compute_verdict, exit_code


def _f(sev):
    return Finding(
        rule_id="X",
        severity=sev,
        message="",
        subject="",
        line=0,
    )


class ComputeVerdictTests(unittest.TestCase):
    def test_no_files(self):
        self.assertIs(compute_verdict([], 0, Options()), Verdict.UNKNOWN)

    def test_healthy(self):
        self.assertIs(compute_verdict([], 1, Options()), Verdict.HEALTHY)

    def test_medium_only(self):
        self.assertIs(
            compute_verdict([_f(Severity.MEDIUM)], 1, Options()),
            Verdict.NEEDS_ATTENTION,
        )

    def test_high_dominates(self):
        self.assertIs(
            compute_verdict(
                [_f(Severity.MEDIUM), _f(Severity.HIGH)], 1, Options()),
            Verdict.UNHEALTHY,
        )

    def test_info_only_default_healthy(self):
        self.assertIs(
            compute_verdict([_f(Severity.INFO)], 1, Options()),
            Verdict.HEALTHY,
        )

    def test_info_only_strict_needs_attention(self):
        self.assertIs(
            compute_verdict(
                [_f(Severity.INFO)], 1, Options(strict=True)),
            Verdict.NEEDS_ATTENTION,
        )


class ExitCodeTests(unittest.TestCase):
    def test_healthy_is_zero(self):
        self.assertEqual(exit_code(Verdict.HEALTHY, Options()), 0)

    def test_needs_attention_is_one(self):
        self.assertEqual(
            exit_code(Verdict.NEEDS_ATTENTION, Options()), 1,
        )

    def test_unhealthy_is_two(self):
        self.assertEqual(exit_code(Verdict.UNHEALTHY, Options()), 2)

    def test_unknown_default_one(self):
        self.assertEqual(exit_code(Verdict.UNKNOWN, Options()), 1)


if __name__ == "__main__":
    unittest.main()
