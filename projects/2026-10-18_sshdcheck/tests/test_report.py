"""Report-layer tests."""

from __future__ import annotations

import io
import json
import unittest

from sshdcheck.report import write_json, write_text
from sshdcheck.types import Finding, ScanResult, Severity, Verdict


def _result(*findings: Finding) -> ScanResult:
    r = ScanResult(
        findings=list(findings),
        files_scanned=1,
        directives_scanned=10,
        verdict=(
            Verdict.UNHEALTHY if any(
                f.severity is Severity.HIGH for f in findings
            ) else Verdict.HEALTHY
        ),
    )
    return r


class WriteTextTests(unittest.TestCase):
    def test_clean_summary(self):
        buf = io.StringIO()
        write_text(_result(), buf)
        self.assertIn("findings=0", buf.getvalue())
        self.assertIn("healthy", buf.getvalue())

    def test_finding_includes_citation_and_hint(self):
        f = Finding(
            rule_id="SSH-001", severity=Severity.HIGH,
            message="PermitRootLogin is yes",
            directive="PermitRootLogin", line=7, path="fx",
            hint="set PermitRootLogin no",
            citation="CIS 5.2.7",
        )
        buf = io.StringIO()
        write_text(_result(f), buf)
        text = buf.getvalue()
        self.assertIn("SSH-001", text)
        self.assertIn("fx:7", text)
        self.assertIn("hint:", text)
        self.assertIn("cite:", text)
        self.assertIn("CIS 5.2.7", text)

    def test_non_ascii_message_is_escaped_as_u_plus_hex(self):
        # Simulate a bidi character embedded in a hint / message.
        bidi = chr(0x202E)
        f = Finding(
            rule_id="SSH-004", severity=Severity.HIGH,
            message="unexpected char " + bidi + " in file",
            directive="Protocol", line=1, path="fx",
            hint="",
            citation="",
        )
        buf = io.StringIO()
        write_text(_result(f), buf)
        text = buf.getvalue()
        self.assertNotIn(bidi, text)
        self.assertIn("<U+202E>", text)

    def test_text_report_never_crashes_on_cp1252_console(self):
        """The report must encode cleanly even on a Windows cp1252 console."""
        bidi = chr(0x202E)
        f = Finding(
            rule_id="SSH-004", severity=Severity.HIGH,
            message="unexpected char " + bidi,
            directive="Protocol", line=1, path="fx",
            hint="", citation="",
        )
        buf = io.StringIO()
        write_text(_result(f), buf)
        # Encode under cp1252 (lossless given the <U+...> escape).
        buf.getvalue().encode("cp1252")


class WriteJsonTests(unittest.TestCase):
    def test_json_shape(self):
        f = Finding(
            rule_id="SSH-001", severity=Severity.HIGH, message="m",
            directive="PermitRootLogin", line=1, path="p",
        )
        buf = io.StringIO()
        write_json(_result(f), buf)
        d = json.loads(buf.getvalue())
        self.assertEqual(d["verdict"], "unhealthy")
        self.assertEqual(d["findings"][0]["rule_id"], "SSH-001")

    def test_json_default_ensure_ascii_is_safe(self):
        f = Finding(
            rule_id="SSH-004", severity=Severity.HIGH,
            message="x " + chr(0x202E),
            directive="Protocol", line=1, path="p",
        )
        buf = io.StringIO()
        write_json(_result(f), buf)
        # json.dump with default ensure_ascii=True escapes the raw
        # codepoint as the backslash-u-escape form in the output.
        self.assertNotIn(chr(0x202E), buf.getvalue())
        self.assertIn("\\u202e", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
