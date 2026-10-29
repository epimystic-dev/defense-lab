"""Report tests - text and JSON output, non-ASCII rendering."""

from __future__ import annotations

import io
import json
import unittest

from tests import support  # noqa: F401

from composecheck.report import _visible, write_json, write_text
from composecheck.types import Finding, ScanResult, Severity, Verdict


class VisibleRenderTests(unittest.TestCase):
    def test_ascii_unchanged(self):
        self.assertEqual(_visible("hello"), "hello")

    def test_non_ascii_rendered_as_codepoint(self):
        text = "a" + chr(0x200B) + "b"
        self.assertEqual(_visible(text), "a<U+200B>b")


class WriteTextTests(unittest.TestCase):
    def test_no_findings_summary_line(self):
        r = ScanResult(files_scanned=1, instructions_scanned=3)
        r.verdict = Verdict.HEALTHY
        out = io.StringIO()
        write_text(r, out)
        self.assertIn("healthy", out.getvalue())
        self.assertIn("findings=0", out.getvalue())

    def test_findings_header_shape(self):
        r = ScanResult(files_scanned=1, instructions_scanned=1)
        r.verdict = Verdict.UNHEALTHY
        r.findings.append(Finding(
            rule_id="DKF-001",
            severity=Severity.HIGH,
            message="demo",
            subject="USER",
            line=4,
            path="Dockerfile",
            hint="h",
            citation="CIS Docker Benchmark 4.1",
        ))
        out = io.StringIO()
        write_text(r, out)
        body = out.getvalue()
        self.assertIn("HIGH DKF-001 Dockerfile:4", body)
        self.assertIn("[USER]: demo", body)
        self.assertIn("hint: h", body)
        self.assertIn("cite: CIS Docker Benchmark 4.1", body)


class WriteJsonTests(unittest.TestCase):
    def test_json_round_trip(self):
        r = ScanResult(files_scanned=1, instructions_scanned=1)
        r.verdict = Verdict.UNHEALTHY
        r.findings.append(Finding(
            rule_id="DKF-001",
            severity=Severity.HIGH,
            message="demo",
            subject="USER",
            line=4,
            path="Dockerfile",
        ))
        out = io.StringIO()
        write_json(r, out)
        parsed = json.loads(out.getvalue())
        self.assertEqual(parsed["verdict"], "unhealthy")
        self.assertEqual(parsed["findings"][0]["rule_id"], "DKF-001")


if __name__ == "__main__":
    unittest.main()
