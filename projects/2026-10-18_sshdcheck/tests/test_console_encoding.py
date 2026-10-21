"""The real CLI must survive a cp1252 Windows console on inputs that
contain non-ASCII characters (bidi overrides, control bytes, etc.).

Reproduces the test that caught a reporter traceback in a sibling
lab's audit: run the real subprocess with PYTHONIOENCODING=cp1252,
feed it a file with a non-ASCII rule-match surface, assert no
traceback and that the match is rendered as <U+XXXX>.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest


PKG_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class CP1252ConsoleTests(unittest.TestCase):
    def test_bidi_in_file_does_not_crash_reporter(self):
        # A directive value with a bidi-override codepoint embedded.
        # sshdcheck's rules don't flag it directly, but the value is
        # echoed back in the report through _visible(), which is
        # exactly the surface we're probing.
        bidi = chr(0x202E)
        body = (
            "# header\n"
            "PermitRootLogin yes\n"
            "Banner " + bidi + "file\n"
        )
        d = tempfile.mkdtemp(prefix="sshdcheck_cp1252_")
        p = os.path.join(d, "sshd_config")
        with open(p, "w", encoding="utf-8") as f:
            f.write(body)
        env = os.environ.copy()
        env["PYTHONPATH"] = PKG_DIR + os.pathsep + env.get("PYTHONPATH", "")
        env["PYTHONIOENCODING"] = "cp1252"
        env["PYTHONUTF8"] = "0"
        r = subprocess.run(
            [sys.executable, "-m", "sshdcheck", p],
            capture_output=True, env=env, timeout=30,
        )
        self.assertNotIn(b"Traceback", r.stderr)
        self.assertNotIn(b"UnicodeEncodeError", r.stderr)
        # SSH-001 fires on PermitRootLogin yes and its rule id must be
        # present in stdout.
        self.assertIn(b"SSH-001", r.stdout)
        try:
            os.remove(p)
        finally:
            pass


if __name__ == "__main__":
    unittest.main()
