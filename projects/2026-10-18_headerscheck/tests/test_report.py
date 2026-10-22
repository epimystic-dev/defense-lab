"""Report-layer tests."""

from __future__ import annotations

import io
import json
import unittest

from headerscheck.report import write_json, write_text
from headerscheck.types import Finding, ScanResult, Severity, Verdict


def _result(*findings: Finding) -> ScanResult:
    return ScanResult(
        findings=list(findings),
        files_scanned=1,
        responses_scanned=1,
        verdict=(
            Verdict.UNHEALTHY
            if any(f.severity is Severity.HIGH for f in findings)
            else Verdict.HEALTHY
        ),
    )


class WriteTextTests(unittest.TestCase):
    def test_clean_summary(self):
        buf = io.StringIO()
        write_text(_result(), buf)
        self.assertIn("findings=0", buf.getvalue())

    def test_finding_includes_citation(self):
        f = Finding(
            rule_id="HDR-001", severity=Severity.HIGH,
            message="HSTS missing", header="Strict-Transport-Security",
            path="fx", hint="add it", citation="RFC 6797",
        )
        buf = io.StringIO()
        write_text(_result(f), buf)
        text = buf.getvalue()
        self.assertIn("HDR-001", text)
        self.assertIn("hint:", text)
        self.assertIn("RFC 6797", text)

    def test_non_ascii_is_escaped(self):
        bidi = chr(0x202E)
        f = Finding(
            rule_id="HDR-X", severity=Severity.HIGH,
            message="x " + bidi + " y",
            header="X", path="fx",
        )
        buf = io.StringIO()
        write_text(_result(f), buf)
        text = buf.getvalue()
        self.assertNotIn(bidi, text)
        self.assertIn("<U+202E>", text)

    def test_cp1252_encoding_survives(self):
        bidi = chr(0x202E)
        f = Finding(
            rule_id="HDR-X", severity=Severity.HIGH,
            message="x " + bidi,
            header="X", path="fx",
        )
        buf = io.StringIO()
        write_text(_result(f), buf)
        buf.getvalue().encode("cp1252")


class WriteJsonTests(unittest.TestCase):
    def test_json_shape(self):
        f = Finding(
            rule_id="HDR-001", severity=Severity.HIGH,
            message="m", header="h", path="p",
        )
        buf = io.StringIO()
        write_json(_result(f), buf)
        d = json.loads(buf.getvalue())
        self.assertEqual(d["verdict"], "unhealthy")
        self.assertEqual(d["findings"][0]["rule_id"], "HDR-001")


if __name__ == "__main__":
    unittest.main()
