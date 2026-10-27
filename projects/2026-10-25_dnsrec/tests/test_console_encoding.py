"""Console-encoding safety: dnsrec must not crash on a cp1252 console
when the input contains a non-Latin-1 character. The text report
renders every non-ASCII character as <U+XXXX>, so the reporter never
tries to encode a character the console cannot.
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
        # Owner carries a zero-width space U+200B; a cp1252 console
        # cannot encode it. The reporter MUST render <U+200B> instead
        # of raw.
        payload = (
            "$ORIGIN example.invalid.\n"
            "sub" + chr(0x200B) + "  IN TXT \"v=DMARC1; p=reject; sp=reject;"
            " adkim=s; aspf=s; rua=mailto:a@example.invalid\"\n"
        )
        d, p = write_temp(payload, name="z.zone")
        try:
            env = os.environ.copy()
            env["PYTHONIOENCODING"] = "cp1252"
            env["PYTHONPATH"] = PKG_DIR + os.pathsep + env.get("PYTHONPATH", "")
            res = subprocess.run(
                [sys.executable, "-m", "dnsrec", p],
                capture_output=True,
                env=env,
                timeout=30,
            )
            # No traceback in stderr: this is the specific regression
            # being guarded against.
            self.assertNotIn(b"Traceback", res.stderr)
            # Non-ASCII must be rendered as <U+XXXX>, not raw.
            self.assertIn(b"<U+200B>", res.stdout)
        finally:
            os.remove(p)


if __name__ == "__main__":
    unittest.main()
