"""Tests for the typed shape surface."""

from __future__ import annotations

import unittest

from headerscheck.types import (
    Finding, Options, ScanResult, Severity, Verdict,
)


class SeverityVerdictTests(unittest.TestCase):
    def test_severity_values(self):
        self.assertEqual(Severity.HIGH.value, "HIGH")
        self.assertEqual(Severity.MEDIUM.value, "MEDIUM")
        self.assertEqual(Severity.INFO.value, "INFO")

    def test_verdict_values(self):
        for v, s in (
            (Verdict.HEALTHY, "healthy"),
            (Verdict.NEEDS_ATTENTION, "needs-attention"),
            (Verdict.UNHEALTHY, "unhealthy"),
            (Verdict.UNKNOWN, "unknown"),
        ):
            self.assertEqual(v.value, s)


class FindingTests(unittest.TestCase):
    def test_to_dict(self):
        f = Finding(
            rule_id="HDR-001", severity=Severity.HIGH, message="m",
            header="h", path="p", hint="hint", citation="c",
        )
        d = f.to_dict()
        self.assertEqual(d["rule_id"], "HDR-001")
        self.assertEqual(d["severity"], "HIGH")
        self.assertEqual(d["citation"], "c")


class ScanResultTests(unittest.TestCase):
    def test_defaults(self):
        r = ScanResult()
        self.assertEqual(r.verdict, Verdict.UNKNOWN)
        self.assertEqual(r.files_scanned, 0)


class OptionsTests(unittest.TestCase):
    def test_rule_enabled_defaults_true(self):
        self.assertTrue(Options().rule_enabled("HDR-001"))

    def test_disabled(self):
        self.assertFalse(
            Options(disabled=("HDR-001",)).rule_enabled("HDR-001"))

    def test_only(self):
        o = Options(only=("HDR-002",))
        self.assertFalse(o.rule_enabled("HDR-001"))
        self.assertTrue(o.rule_enabled("HDR-002"))


if __name__ == "__main__":
    unittest.main()
