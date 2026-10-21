"""Tests for the typed shape surface."""

from __future__ import annotations

import unittest

from sshdcheck.types import (
    Finding, Options, ScanResult, Severity, Verdict,
)


class SeverityVerdictTests(unittest.TestCase):
    def test_severity_values(self):
        self.assertEqual(Severity.HIGH.value, "HIGH")
        self.assertEqual(Severity.MEDIUM.value, "MEDIUM")
        self.assertEqual(Severity.INFO.value, "INFO")

    def test_verdict_values(self):
        self.assertEqual(Verdict.HEALTHY.value, "healthy")
        self.assertEqual(Verdict.NEEDS_ATTENTION.value, "needs-attention")
        self.assertEqual(Verdict.UNHEALTHY.value, "unhealthy")
        self.assertEqual(Verdict.UNKNOWN.value, "unknown")


class FindingTests(unittest.TestCase):
    def test_to_dict_roundtrips_fields(self):
        f = Finding(
            rule_id="SSH-001", severity=Severity.HIGH, message="m",
            directive="PermitRootLogin", line=7, path="p",
            hint="h", citation="c",
        )
        d = f.to_dict()
        self.assertEqual(d["rule_id"], "SSH-001")
        self.assertEqual(d["severity"], "HIGH")
        self.assertEqual(d["line"], 7)
        self.assertEqual(d["citation"], "c")


class ScanResultTests(unittest.TestCase):
    def test_defaults(self):
        r = ScanResult()
        self.assertEqual(r.findings, [])
        self.assertEqual(r.files_scanned, 0)
        self.assertEqual(r.directives_scanned, 0)
        self.assertEqual(r.verdict, Verdict.UNKNOWN)

    def test_to_dict_shape(self):
        r = ScanResult(
            findings=[], files_scanned=1, directives_scanned=10,
            verdict=Verdict.HEALTHY,
        )
        d = r.to_dict()
        self.assertEqual(d["verdict"], "healthy")
        self.assertEqual(d["files_scanned"], 1)
        self.assertEqual(d["directives_scanned"], 10)
        self.assertEqual(d["findings"], [])


class OptionsTests(unittest.TestCase):
    def test_default_rule_enabled(self):
        self.assertTrue(Options().rule_enabled("SSH-001"))

    def test_disabled_suppresses(self):
        self.assertFalse(
            Options(disabled=("SSH-001",)).rule_enabled("SSH-001"))

    def test_only_restricts(self):
        o = Options(only=("SSH-002",))
        self.assertFalse(o.rule_enabled("SSH-001"))
        self.assertTrue(o.rule_enabled("SSH-002"))


if __name__ == "__main__":
    unittest.main()
