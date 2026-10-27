"""Scanner tests (scan_text, scan_file, scan_paths)."""

from __future__ import annotations

import os
import unittest

from tests import support  # noqa: F401
from tests.support import write_temp

from dnsrec.scanner import scan_file, scan_paths, scan_text
from dnsrec.types import Options, Verdict


HEALTHY = (
    "$ORIGIN example.invalid.\n"
    "@  IN TXT \"v=spf1 -all\"\n"
    "_dmarc  IN TXT \"v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s; "
    "rua=mailto:a@example.invalid\"\n"
)


WEAK = (
    "$ORIGIN example.invalid.\n"
    "@  IN TXT \"v=spf1 +all\"\n"
    "@  IN TXT \"v=spf1 -all\"\n"
)


class ScanTextTests(unittest.TestCase):
    def test_healthy_text_verdict_healthy(self):
        r = scan_text(HEALTHY, "in-memory", Options())
        self.assertEqual(r.verdict, Verdict.HEALTHY)

    def test_weak_text_verdict_unhealthy(self):
        r = scan_text(WEAK, "in-memory", Options())
        self.assertEqual(r.verdict, Verdict.UNHEALTHY)


class ScanFileTests(unittest.TestCase):
    def test_missing_file_reports_dnsrec_000(self):
        r = scan_file("definitely-not-here.zone", Options())
        self.assertEqual(r.verdict, Verdict.UNHEALTHY)
        self.assertEqual(r.findings[0].rule_id, "DNSREC-000")

    def test_file_round_trip(self):
        d, p = write_temp(HEALTHY)
        try:
            r = scan_file(p, Options())
            self.assertEqual(r.verdict, Verdict.HEALTHY)
        finally:
            os.remove(p)


class ScanPathsTests(unittest.TestCase):
    def test_many_files_merge(self):
        d1, p1 = write_temp(HEALTHY)
        d2, p2 = write_temp(WEAK)
        try:
            r = scan_paths([p1, p2], Options())
            # Weak wins the merged verdict.
            self.assertEqual(r.verdict, Verdict.UNHEALTHY)
            self.assertEqual(r.files_scanned, 2)
        finally:
            os.remove(p1)
            os.remove(p2)

    def test_directory_input_reports_error(self):
        d, p = write_temp(HEALTHY)
        try:
            r = scan_paths([os.path.dirname(p)], Options())
            # The directory itself is rejected with a DNSREC-000 note.
            self.assertTrue(any(
                f.rule_id == "DNSREC-000" for f in r.findings))
        finally:
            os.remove(p)


if __name__ == "__main__":
    unittest.main()
