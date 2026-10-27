"""Shape tests for the dnsrec datatypes."""

from __future__ import annotations

import unittest

from tests import support  # noqa: F401

from dnsrec.types import (
    Finding,
    Options,
    Record,
    RecordKind,
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


class RecordKindTests(unittest.TestCase):
    def test_enum_values(self):
        self.assertEqual(RecordKind.SPF.value, "spf")
        self.assertEqual(RecordKind.DMARC.value, "dmarc")
        self.assertEqual(RecordKind.DKIM.value, "dkim")
        self.assertEqual(RecordKind.OTHER.value, "other")


class FindingTests(unittest.TestCase):
    def test_to_dict_round_trip(self):
        f = Finding(
            rule_id="SPF-001",
            severity=Severity.HIGH,
            message="demo",
            owner="example.invalid",
            line=3,
            path="/x",
            hint="h",
            citation="c",
        )
        d = f.to_dict()
        self.assertEqual(d["rule_id"], "SPF-001")
        self.assertEqual(d["severity"], "HIGH")
        self.assertEqual(d["owner"], "example.invalid")
        self.assertEqual(d["line"], 3)
        self.assertEqual(d["hint"], "h")
        self.assertEqual(d["citation"], "c")


class ScanResultTests(unittest.TestCase):
    def test_defaults_and_to_dict(self):
        r = ScanResult()
        self.assertEqual(r.verdict, Verdict.UNKNOWN)
        self.assertEqual(r.files_scanned, 0)
        self.assertEqual(r.records_scanned, 0)
        d = r.to_dict()
        self.assertEqual(d["verdict"], "unknown")
        self.assertEqual(d["findings"], [])


class RecordTests(unittest.TestCase):
    def test_record_fields(self):
        rec = Record(
            owner="example.invalid",
            kind=RecordKind.SPF,
            value="v=spf1 -all",
            line=1,
            raw="example.invalid IN TXT \"v=spf1 -all\"",
        )
        self.assertEqual(rec.owner, "example.invalid")
        self.assertIs(rec.kind, RecordKind.SPF)


class OptionsTests(unittest.TestCase):
    def test_default_rule_enabled(self):
        o = Options()
        self.assertTrue(o.rule_enabled("SPF-001"))

    def test_disabled_rule(self):
        o = Options(disabled=("SPF-001",))
        self.assertFalse(o.rule_enabled("SPF-001"))
        self.assertTrue(o.rule_enabled("SPF-002"))

    def test_only_filter(self):
        o = Options(only=("SPF-003",))
        self.assertTrue(o.rule_enabled("SPF-003"))
        self.assertFalse(o.rule_enabled("SPF-001"))


if __name__ == "__main__":
    unittest.main()
