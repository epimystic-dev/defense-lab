"""The real CLI must survive a cp1252 Windows console on inputs that
contain non-ASCII characters.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest


PKG_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class CP1252ConsoleTests(unittest.TestCase):
    def test_bidi_in_header_value_does_not_crash_reporter(self):
        bidi = chr(0x202E)
        body = (
            "HTTP/1.1 200 OK\n"
            "Content-Type: text/html\n"
            "Server: nginx/" + bidi + "1.18.0\n"
            "\n"
        )
        d = tempfile.mkdtemp(prefix="headerscheck_cp1252_")
        p = os.path.join(d, "response.http")
        with open(p, "w", encoding="utf-8") as f:
            f.write(body)
        env = os.environ.copy()
        env["PYTHONPATH"] = PKG_DIR + os.pathsep + env.get("PYTHONPATH", "")
        env["PYTHONIOENCODING"] = "cp1252"
        env["PYTHONUTF8"] = "0"
        r = subprocess.run(
            [sys.executable, "-m", "headerscheck",
             "--assume-https", "--include-info", p],
            capture_output=True, env=env, timeout=30,
        )
        self.assertNotIn(b"Traceback", r.stderr)
        self.assertNotIn(b"UnicodeEncodeError", r.stderr)
        self.assertIn(b"HDR-001", r.stdout)
        os.remove(p)


if __name__ == "__main__":
    unittest.main()
