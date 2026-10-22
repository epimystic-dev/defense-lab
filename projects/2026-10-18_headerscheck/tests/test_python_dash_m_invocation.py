"""`python -m headerscheck` behaves the same as calling cli.main."""

from __future__ import annotations

import os
import subprocess
import sys
import unittest


PKG_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXAMPLES = os.path.join(PKG_DIR, "examples")


def _run(*args):
    env = os.environ.copy()
    env["PYTHONPATH"] = PKG_DIR + os.pathsep + env.get("PYTHONPATH", "")
    return subprocess.run(
        [sys.executable, "-m", "headerscheck", *args],
        capture_output=True, text=True, env=env, timeout=30,
    )


class DashMTests(unittest.TestCase):
    def test_version(self):
        r = _run("--version")
        self.assertEqual(r.returncode, 0)
        self.assertTrue(r.stdout.startswith("headerscheck "))

    def test_healthy_fixture_rc_zero(self):
        r = _run(os.path.join(EXAMPLES, "healthy_response.http"))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_weak_fixture_fires(self):
        r = _run(os.path.join(EXAMPLES, "weak_response.http"))
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("HDR-001", r.stdout)
        self.assertIn("HDR-013", r.stdout)
        self.assertIn("HDR-016", r.stdout)


if __name__ == "__main__":
    unittest.main()
