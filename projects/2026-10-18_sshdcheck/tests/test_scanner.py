"""Scanner-level tests."""

from __future__ import annotations

import os
import unittest

from sshdcheck.scanner import scan_file, scan_paths, scan_text
from sshdcheck.types import Options, Verdict

from tests.support import rule_ids, write_temp


HEALTHY = """\
Port 22
Protocol 2
PermitRootLogin no
PasswordAuthentication no
PermitEmptyPasswords no
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

WEAK = """\
PermitRootLogin yes
PasswordAuthentication yes
PermitEmptyPasswords yes
HostbasedAuthentication yes
IgnoreRhosts no
MaxAuthTries 10
X11Forwarding yes
UsePAM no
Ciphers aes128-cbc
MACs hmac-md5
KexAlgorithms diffie-hellman-group1-sha1
"""


class ScanTextTests(unittest.TestCase):
    def test_healthy_text_is_healthy(self):
        r = scan_text(HEALTHY, "healthy", Options())
        self.assertEqual(r.verdict, Verdict.HEALTHY)
        self.assertEqual(r.findings, [])
        self.assertEqual(r.files_scanned, 1)

    def test_weak_text_is_unhealthy(self):
        r = scan_text(WEAK, "weak", Options())
        self.assertEqual(r.verdict, Verdict.UNHEALTHY)
        self.assertIn("SSH-001", rule_ids(r.findings))


class ScanFileTests(unittest.TestCase):
    def test_file_round_trips(self):
        _d, p = write_temp(HEALTHY)
        try:
            r = scan_file(p, Options())
            self.assertEqual(r.verdict, Verdict.HEALTHY)
        finally:
            os.remove(p)

    def test_missing_file_produces_ssh_000(self):
        r = scan_file(
            os.path.join(os.path.dirname(__file__), "no-such-file"),
            Options())
        self.assertEqual(r.verdict, Verdict.UNHEALTHY)
        self.assertIn("SSH-000", rule_ids(r.findings))


class ScanPathsTests(unittest.TestCase):
    def test_directory_scan_picks_up_sshd_config(self):
        d, _p = write_temp(WEAK)
        try:
            r = scan_paths([d], Options())
            self.assertEqual(r.verdict, Verdict.UNHEALTHY)
            self.assertEqual(r.files_scanned, 1)
        finally:
            # support.write_temp made a fresh temp dir; clean the file.
            for name in os.listdir(d):
                os.remove(os.path.join(d, name))

    def test_scan_paths_merges_two_files(self):
        d1, p1 = write_temp(HEALTHY)
        d2, p2 = write_temp(WEAK)
        try:
            r = scan_paths([p1, p2], Options())
            self.assertEqual(r.files_scanned, 2)
            self.assertEqual(r.verdict, Verdict.UNHEALTHY)
        finally:
            for p in (p1, p2):
                if os.path.exists(p):
                    os.remove(p)


if __name__ == "__main__":
    unittest.main()
