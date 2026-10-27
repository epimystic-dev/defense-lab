"""In-process CLI tests."""

from __future__ import annotations

import json
import os
import unittest

from tests import support  # noqa: F401
from tests.support import run_cli, write_temp


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


def _safe_run(argv):
    """Call run_cli but intercept SystemExit (argparse exits for --help)."""
    try:
        return run_cli(argv)
    except SystemExit as e:
        return (
            int(e.code) if isinstance(e.code, int) else 2,
            "dnsrec ",
            "",
        )


class HelpAndVersionTests(unittest.TestCase):
    def test_help_rc_zero(self):
        rc, out, _err = _safe_run(["--help"])
        self.assertEqual(rc, 0)

    def test_version_rc_zero(self):
        rc, _out, _err = _safe_run(["--version"])
        self.assertEqual(rc, 0)

    def test_unknown_flag_rc_two(self):
        rc, _out, _err = _safe_run(["--not-a-flag", "/tmp/x"])
        self.assertEqual(rc, 2)


class JsonAndTextTests(unittest.TestCase):
    def setUp(self):
        self._d_h, self._healthy = write_temp(HEALTHY, name="h.zone")
        self._d_w, self._weak = write_temp(WEAK, name="w.zone")

    def tearDown(self):
        for p in (self._healthy, self._weak):
            if os.path.exists(p):
                os.remove(p)

    def test_text_output_prints_rule_ids(self):
        rc, out, _ = run_cli([self._weak])
        self.assertNotEqual(rc, 0)
        self.assertIn("SPF-001", out)
        self.assertIn("SPF-003", out)

    def test_json_output_parses(self):
        rc, out, _ = run_cli(["--json", self._weak])
        self.assertNotEqual(rc, 0)
        parsed = json.loads(out)
        self.assertEqual(parsed["verdict"], "unhealthy")
        self.assertTrue(parsed["findings"])

    def test_healthy_rc_zero(self):
        rc, _out, _ = run_cli([self._healthy])
        self.assertEqual(rc, 0)

    def test_disable_suppresses_rule(self):
        rc, out, _ = run_cli(["--disable", "SPF-001", self._weak])
        self.assertNotEqual(rc, 0)
        self.assertNotIn("SPF-001", out)


class KindFlagTests(unittest.TestCase):
    def test_kind_spf_bare_input(self):
        bare = "v=spf1 +all\n"
        d, p = write_temp(bare, name="bare.spf")
        try:
            rc, out, _ = run_cli(["--kind", "spf", p])
            self.assertNotEqual(rc, 0)
            self.assertIn("SPF-003", out)
        finally:
            os.remove(p)

    def test_kind_dmarc_bare_input(self):
        bare = "v=DMARC1; p=none\n"
        d, p = write_temp(bare, name="bare.dmarc")
        try:
            rc, out, _ = run_cli(["--kind", "dmarc", p])
            self.assertNotEqual(rc, 0)
            self.assertIn("DMARC-001", out)
        finally:
            os.remove(p)

    def test_kind_dkim_bare_input(self):
        bare = "v=DKIM1; k=rsa; p=\n"
        d, p = write_temp(bare, name="bare.dkim")
        try:
            rc, out, _ = run_cli(["--kind", "dkim", p])
            self.assertNotEqual(rc, 0)
            self.assertIn("DKIM-003", out)
        finally:
            os.remove(p)


class StrictModeTests(unittest.TestCase):
    def test_strict_surfaces_info_rules(self):
        text = (
            "$ORIGIN example.invalid.\n"
            "sel._domainkey  IN TXT \"v=DKIM1; k=rsa; g=*; p=aGVsbG8=\"\n"
        )
        d, p = write_temp(text, name="dkim.zone")
        try:
            rc, out, _ = run_cli(["--strict", p])
            self.assertNotEqual(rc, 0)
            self.assertIn("DKIM-006", out)
        finally:
            os.remove(p)


if __name__ == "__main__":
    unittest.main()
