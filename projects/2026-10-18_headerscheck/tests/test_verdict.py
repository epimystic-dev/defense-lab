"""Verdict rollup tests."""

from __future__ import annotations

import unittest

from headerscheck.types import Finding, Options, Severity, Verdict
from headerscheck.verdict import compute_verdict, exit_code


def _f(sev):
    return Finding(
        rule_id="HDR-X", severity=sev, message="",
        header="", path="",
    )


class ComputeVerdictTests(unittest.TestCase):
    def test_no_findings_is_healthy(self):
        self.assertEqual(
            compute_verdict([], 1, Options()), Verdict.HEALTHY)

    def test_high_dominates(self):
        v = compute_verdict(
            [_f(Severity.HIGH), _f(Severity.MEDIUM)], 1, Options())
        self.assertEqual(v, Verdict.UNHEALTHY)

    def test_medium_without_high(self):
        self.assertEqual(
            compute_verdict([_f(Severity.MEDIUM)], 1, Options()),
            Verdict.NEEDS_ATTENTION)

    def test_info_only_default(self):
        self.assertEqual(
            compute_verdict([_f(Severity.INFO)], 1, Options()),
            Verdict.HEALTHY)

    def test_info_only_strict(self):
        self.assertEqual(
            compute_verdict(
                [_f(Severity.INFO)], 1, Options(strict=True)),
            Verdict.NEEDS_ATTENTION)

    def test_no_files(self):
        self.assertEqual(
            compute_verdict([], 0, Options()), Verdict.UNKNOWN)


class ExitCodeTests(unittest.TestCase):
    def test_values(self):
        self.assertEqual(exit_code(Verdict.HEALTHY, Options()), 0)
        self.assertEqual(exit_code(Verdict.NEEDS_ATTENTION, Options()), 1)
        self.assertEqual(exit_code(Verdict.UNHEALTHY, Options()), 2)
        self.assertEqual(exit_code(Verdict.UNKNOWN, Options()), 1)
        self.assertEqual(
            exit_code(Verdict.UNKNOWN, Options(strict=True)), 2)


if __name__ == "__main__":
    unittest.main()
