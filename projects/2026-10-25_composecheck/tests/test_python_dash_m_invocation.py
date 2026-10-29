"""python -m composecheck is the invocation documented in the engineering
contract. This test fails loudly if the __main__ entry stops working.
"""

from __future__ import annotations

import os
import subprocess
import sys
import unittest

from tests import support  # noqa: F401


PKG_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class PythonDashMTests(unittest.TestCase):
    def _run(self, *args):
        env = os.environ.copy()
        env["PYTHONPATH"] = PKG_DIR + os.pathsep + env.get("PYTHONPATH", "")
        return subprocess.run(
            [sys.executable, "-m", "composecheck", *args],
            capture_output=True,
            text=True,
            env=env,
            timeout=30,
        )

    def test_version_subcommand(self):
        r = self._run("--version")
        self.assertEqual(r.returncode, 0)
        self.assertTrue(r.stdout.startswith("composecheck "))

    def test_help_subcommand(self):
        r = self._run("--help")
        self.assertEqual(r.returncode, 0)
        self.assertIn("composecheck", r.stdout)


if __name__ == "__main__":
    unittest.main()
