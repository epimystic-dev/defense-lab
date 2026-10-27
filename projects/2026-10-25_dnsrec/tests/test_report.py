"""Report tests - text and JSON output, non-ASCII rendering."""

from __future__ import annotations

import io
import json
import unittest

from tests import support  # noqa: F401

from dnsrec.report import _visible, write_json, write_text
from dnsrec.types import Finding, ScanResult, Severity, Verdict


class VisibleRenderTests(unittest.TestCase):
    def test_ascii_unchanged(self):
        self.assertEqual(_visible("hello"), "hello")

    def test_non_ascii_rendered_as_codepoint(self):
        # A zero-width space, a space pretending not to be there.
        text = "a" + chr(0x200B) + "b"
        self.assertEqual(_visible(text), "a<U+200B>b")

    def test_bidi_override_rendered(self):
        text = chr(0x202E) + "hello"
        self.assertEqual(_visible(text), "<U+202E>hello")

    def test_control_character_rendered(self):
        text = "\x1b[31m"
        rendered = _visible(text)
        self.assertNotIn("\x1b", rendered)
        self.assertIn("<U+001B>", rendered)


class WriteTextTests(unittest.TestCase):
    def test_no_findings_summary_line(self):
        r = ScanResult(files_scanned=1, records_scanned=3)
        r.verdict = Verdict.HEALTHY
        out = io.StringIO()
        write_text(r, out)
        self.assertIn("healthy", out.getvalue())
        self.assertIn("findings=0", out.getvalue())

    def test_findings_header_shape(self):
        r = ScanResult(files_scanned=1, records_scanned=1)
        r.verdict = Verdict.UNHEALTHY
        r.findings.append(Finding(
            rule_id="SPF-001",
            severity=Severity.HIGH,
            message="demo",
            owner="example.invalid",
            line=4,
            path="demo.zone",
            hint="h",
            citation="RFC 7208 section 3.2",
        ))
        out = io.StringIO()
        write_text(r, out)
        body = out.getvalue()
        self.assertIn("HIGH SPF-001 demo.zone:4", body)
        self.assertIn("[example.invalid]: demo", body)
        self.assertIn("hint: h", body)
        self.assertIn("cite: RFC 7208 section 3.2", body)


class WriteJsonTests(unittest.TestCase):
    def test_json_round_trip(self):
        r = ScanResult(files_scanned=1, records_scanned=1)
        r.verdict = Verdict.UNHEALTHY
        r.findings.append(Finding(
            rule_id="SPF-001",
            severity=Severity.HIGH,
            message="demo",
            owner="example.invalid",
            line=4,
            path="demo.zone",
        ))
        out = io.StringIO()
        write_json(r, out)
        parsed = json.loads(out.getvalue())
        self.assertEqual(parsed["verdict"], "unhealthy")
        self.assertEqual(parsed["findings"][0]["rule_id"], "SPF-001")
        self.assertEqual(parsed["findings"][0]["severity"], "HIGH")


if __name__ == "__main__":
    unittest.main()
