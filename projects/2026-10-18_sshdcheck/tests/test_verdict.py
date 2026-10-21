"""Verdict rollup tests."""

from __future__ import annotations

import unittest

from sshdcheck.types import Finding, Options, Severity, Verdict
from sshdcheck.verdict import compute_verdict, exit_code


def _f(sev: Severity) -> Finding:
    return Finding(
        rule_id="SSH-TEST", severity=sev, message="",
        directive="", line=0, path="",
    )


class ComputeVerdictTests(unittest.TestCase):
    def test_no_findings_is_healthy(self):
        self.assertEqual(
            compute_verdict([], 1, Options()), Verdict.HEALTHY)

    def test_high_dominates(self):
        v = compute_verdict(
            [_f(Severity.HIGH), _f(Severity.MEDIUM)], 1, Options())
        self.assertEqual(v, Verdict.UNHEALTHY)

    def test_medium_without_high_is_needs_attention(self):
        v = compute_verdict([_f(Severity.MEDIUM)], 1, Options())
        self.assertEqual(v, Verdict.NEEDS_ATTENTION)

    def test_info_only_is_healthy_by_default(self):
        v = compute_verdict([_f(Severity.INFO)], 1, Options())
        self.assertEqual(v, Verdict.HEALTHY)

    def test_info_only_is_needs_attention_in_strict(self):
        v = compute_verdict(
            [_f(Severity.INFO)], 1, Options(strict=True))
        self.assertEqual(v, Verdict.NEEDS_ATTENTION)

    def test_no_files_is_unknown(self):
        v = compute_verdict([], 0, Options())
        self.assertEqual(v, Verdict.UNKNOWN)

    def test_io_error_as_high_is_unhealthy_even_with_no_files(self):
        v = compute_verdict([_f(Severity.HIGH)], 0, Options())
        self.assertEqual(v, Verdict.UNHEALTHY)


class ExitCodeTests(unittest.TestCase):
    def test_healthy_zero(self):
        self.assertEqual(exit_code(Verdict.HEALTHY, Options()), 0)

    def test_needs_attention_one(self):
        self.assertEqual(exit_code(Verdict.NEEDS_ATTENTION, Options()), 1)

    def test_unhealthy_two(self):
        self.assertEqual(exit_code(Verdict.UNHEALTHY, Options()), 2)

    def test_unknown_default_one(self):
        self.assertEqual(exit_code(Verdict.UNKNOWN, Options()), 1)

    def test_unknown_strict_two(self):
        self.assertEqual(
            exit_code(Verdict.UNKNOWN, Options(strict=True)), 2)


if __name__ == "__main__":
    unittest.main()
