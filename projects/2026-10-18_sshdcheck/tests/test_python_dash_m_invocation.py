"""`python -m sshdcheck` must behave the same as calling cli.main."""

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
        [sys.executable, "-m", "sshdcheck", *args],
        capture_output=True, text=True, env=env, timeout=30,
    )


class DashMTests(unittest.TestCase):
    def test_module_is_runnable(self):
        r = _run("--version")
        self.assertEqual(r.returncode, 0)
        self.assertTrue(r.stdout.startswith("sshdcheck "))

    def test_healthy_fixture_rc_zero(self):
        r = _run(os.path.join(EXAMPLES, "healthy_sshd_config"))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_weak_fixture_rc_nonzero_and_rule_anchor_present(self):
        r = _run(os.path.join(EXAMPLES, "weak_sshd_config"))
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("SSH-001", r.stdout)
        self.assertIn("SSH-004", r.stdout)
        self.assertIn("SSH-011", r.stdout)


if __name__ == "__main__":
    unittest.main()
