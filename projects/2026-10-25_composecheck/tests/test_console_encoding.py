"""Console-encoding safety: composecheck must not crash on a cp1252
console when the input contains a non-Latin-1 character. The text
report renders every non-ASCII character as <U+XXXX>.
"""

from __future__ import annotations

import os
import subprocess
import sys
import unittest

from tests import support  # noqa: F401
from tests.support import write_temp


PKG_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class ConsoleEncodingTests(unittest.TestCase):
    def test_subprocess_with_cp1252_env_does_not_crash(self):
        # ENV variable name carries a zero-width space U+200B so the
        # finding message (which quotes the name) exercises the
        # non-ASCII rendering path.
        payload = (
            "FROM ubuntu:latest\n"
            "ENV API_KEY" + chr(0x200B) + "=notasecret\n"
        )
        d, p = write_temp(payload, name="Dockerfile")
        try:
            env = os.environ.copy()
            env["PYTHONIOENCODING"] = "cp1252"
            env["PYTHONPATH"] = PKG_DIR + os.pathsep + env.get("PYTHONPATH", "")
            res = subprocess.run(
                [sys.executable, "-m", "composecheck", p],
                capture_output=True,
                env=env,
                timeout=30,
            )
            self.assertNotIn(b"Traceback", res.stderr)
            self.assertIn(b"<U+200B>", res.stdout)
        finally:
            os.remove(p)


if __name__ == "__main__":
    unittest.main()
