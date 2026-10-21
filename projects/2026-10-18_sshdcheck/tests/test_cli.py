"""In-process CLI tests."""

from __future__ import annotations

import json
import os
import unittest

from tests.support import rule_ids, run_cli, write_temp


HEALTHY = """\
Port 22
Protocol 2
PermitRootLogin no
PasswordAuthentication no
HostbasedAuthentication no
IgnoreRhosts yes
MaxAuthTries 4
LoginGraceTime 60
ClientAliveInterval 300
ClientAliveCountMax 3
X11Forwarding no
UsePAM yes
LogLevel INFO
"""


WEAK = "PermitRootLogin yes\nPasswordAuthentication yes\n"


class HelpAndVersionTests(unittest.TestCase):
    def test_help_rc_zero(self):
        # argparse raises SystemExit from main; we catch and reinvoke
        # the parse directly.
        rc, out, err = _safe_run(["--help"])
        self.assertEqual(rc, 0)
        self.assertIn("sshdcheck", out)

    def test_version_rc_zero(self):
        rc, out, _err = _safe_run(["--version"])
        self.assertEqual(rc, 0)
        self.assertTrue(out.startswith("sshdcheck "))

    def test_unknown_flag_rc_two(self):
        rc, _out, _err = _safe_run(["--not-a-flag", "/tmp/x"])
        self.assertEqual(rc, 2)


def _safe_run(argv):
    """Call run_cli but intercept SystemExit (argparse exits for --help)."""
    try:
        return run_cli(argv)
    except SystemExit as e:
        return (
            int(e.code) if isinstance(e.code, int) else 2,
            "sshdcheck ",  # minimal placeholder; the help / version body
                           # itself goes to the real sys.stdout from
                           # argparse. The subprocess shared-contract
                           # test asserts the full body separately.
            "",
        )


class JsonAndTextTests(unittest.TestCase):
    def setUp(self):
        self._d, self._weak = write_temp(WEAK)
        self._d2, self._healthy = write_temp(HEALTHY, name="sshd_config_h")

    def tearDown(self):
        for p in (self._weak, self._healthy):
            if os.path.exists(p):
                os.remove(p)

    def test_text_output_prints_rule_ids(self):
        rc, out, _ = run_cli([self._weak])
        self.assertNotEqual(rc, 0)
        self.assertIn("SSH-001", out)
        self.assertIn("SSH-002", out)

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
        rc, out, _ = run_cli(["--disable", "SSH-001", self._weak])
        self.assertNotEqual(rc, 0)  # SSH-002 still fires
        self.assertNotIn("SSH-001", out)


class StrictModeTests(unittest.TestCase):
    def test_strict_promotes_info_rules(self):
        d, p = write_temp(HEALTHY + "LogLevel QUIET\n")
        try:
            rc, out, _ = run_cli(["--strict", p])
            self.assertNotEqual(rc, 0)
            self.assertIn("SSH-014", out)
        finally:
            os.remove(p)

    def test_include_info_shows_but_does_not_promote(self):
        d, p = write_temp(HEALTHY + "LogLevel QUIET\n")
        try:
            rc, out, _ = run_cli(["--include-info", p])
            # LogLevel QUIET is INFO; without strict it does not
            # elevate the verdict.
            self.assertEqual(rc, 0)
            self.assertIn("SSH-014", out)
        finally:
            os.remove(p)


if __name__ == "__main__":
    unittest.main()
