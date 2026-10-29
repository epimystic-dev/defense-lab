"""In-process CLI tests."""

from __future__ import annotations

import json
import os
import unittest

from tests import support  # noqa: F401
from tests.support import run_cli, write_temp


HEALTHY = (
    "FROM alpine:3.19\n"
    "USER app\n"
    "HEALTHCHECK CMD /bin/true\n"
)

WEAK = (
    "FROM ubuntu:latest\n"
    "ENV API_KEY=notasecret\n"
    "RUN chmod 777 /opt\n"
)


def _safe_run(argv):
    try:
        return run_cli(argv)
    except SystemExit as e:
        return (
            int(e.code) if isinstance(e.code, int) else 2,
            "composecheck ",
            "",
        )


class HelpAndVersionTests(unittest.TestCase):
    def test_help_rc_zero(self):
        rc, _out, _err = _safe_run(["--help"])
        self.assertEqual(rc, 0)

    def test_version_rc_zero(self):
        rc, _out, _err = _safe_run(["--version"])
        self.assertEqual(rc, 0)

    def test_unknown_flag_rc_two(self):
        rc, _out, _err = _safe_run(["--not-a-flag", "/tmp/x"])
        self.assertEqual(rc, 2)


class JsonAndTextTests(unittest.TestCase):
    def setUp(self):
        self._d_h, self._healthy = write_temp(HEALTHY, name="Dockerfile")
        self._d_w, self._weak = write_temp(WEAK, name="Dockerfile.weak")

    def tearDown(self):
        for p in (self._healthy, self._weak):
            if os.path.exists(p):
                os.remove(p)

    def test_text_output_prints_rule_ids(self):
        rc, out, _ = run_cli([self._weak])
        self.assertNotEqual(rc, 0)
        self.assertIn("DKF-001", out)
        self.assertIn("DKF-002", out)

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
        rc, out, _ = run_cli(["--disable", "DKF-001", self._weak])
        self.assertNotEqual(rc, 0)  # DKF-002 still fires
        self.assertNotIn("DKF-001", out)


class AsFlagTests(unittest.TestCase):
    def test_as_dockerfile_forces_parse(self):
        text = "FROM alpine:3.19\nUSER app\nHEALTHCHECK CMD /bin/true\n"
        d, p = write_temp(text, name="arbitrary_name")
        try:
            rc, _out, _ = run_cli(["--as", "dockerfile", p])
            self.assertEqual(rc, 0)
        finally:
            os.remove(p)


if __name__ == "__main__":
    unittest.main()
