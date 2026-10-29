"""Shape tests for the composecheck datatypes."""

from __future__ import annotations

import unittest

from tests import support  # noqa: F401

from composecheck.types import (
    FileKind,
    Finding,
    Options,
    ScanResult,
    Severity,
    Verdict,
)


class SeverityTests(unittest.TestCase):
    def test_enum_values(self):
        self.assertEqual(Severity.HIGH.value, "HIGH")
        self.assertEqual(Severity.MEDIUM.value, "MEDIUM")
        self.assertEqual(Severity.INFO.value, "INFO")


class VerdictTests(unittest.TestCase):
    def test_enum_values(self):
        self.assertEqual(Verdict.HEALTHY.value, "healthy")
        self.assertEqual(Verdict.NEEDS_ATTENTION.value, "needs-attention")
        self.assertEqual(Verdict.UNHEALTHY.value, "unhealthy")
        self.assertEqual(Verdict.UNKNOWN.value, "unknown")


class FileKindTests(unittest.TestCase):
    def test_enum_values(self):
        self.assertEqual(FileKind.DOCKERFILE.value, "dockerfile")
        self.assertEqual(FileKind.COMPOSE.value, "compose")
        self.assertEqual(FileKind.UNKNOWN.value, "unknown")


class FindingTests(unittest.TestCase):
    def test_to_dict_round_trip(self):
        f = Finding(
            rule_id="DKF-001",
            severity=Severity.HIGH,
            message="demo",
            subject="USER",
            line=5,
            path="/x",
            hint="h",
            citation="c",
        )
        d = f.to_dict()
        self.assertEqual(d["rule_id"], "DKF-001")
        self.assertEqual(d["subject"], "USER")
        self.assertEqual(d["line"], 5)


class ScanResultTests(unittest.TestCase):
    def test_defaults_and_to_dict(self):
        r = ScanResult()
        self.assertEqual(r.verdict, Verdict.UNKNOWN)
        d = r.to_dict()
        self.assertEqual(d["verdict"], "unknown")


class OptionsTests(unittest.TestCase):
    def test_default_rule_enabled(self):
        o = Options()
        self.assertTrue(o.rule_enabled("DKF-001"))

    def test_disabled_rule(self):
        o = Options(disabled=("DKF-001",))
        self.assertFalse(o.rule_enabled("DKF-001"))

    def test_only_filter(self):
        o = Options(only=("DC-001",))
        self.assertTrue(o.rule_enabled("DC-001"))
        self.assertFalse(o.rule_enabled("DKF-001"))


if __name__ == "__main__":
    unittest.main()
