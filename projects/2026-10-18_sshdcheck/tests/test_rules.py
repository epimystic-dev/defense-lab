"""Rule-level tests - one focused suite per rule in REGISTRY."""

from __future__ import annotations

import unittest

from sshdcheck.parse import parse_text
from sshdcheck.rules import REGISTRY, run_all
from sshdcheck.types import Options, Severity

from tests.support import scan_string, rule_ids


class Ssh001Tests(unittest.TestCase):
    def test_yes_fires_high(self):
        f = scan_string("PermitRootLogin yes\n")
        self.assertIn("SSH-001", rule_ids(f))
        self.assertEqual(f[0].severity, Severity.HIGH)

    def test_absent_fires_high(self):
        self.assertIn("SSH-001", rule_ids(scan_string("")))

    def test_prohibit_password_is_medium(self):
        f = [x for x in scan_string("PermitRootLogin prohibit-password\n")
             if x.rule_id == "SSH-001"]
        self.assertTrue(f)
        self.assertEqual(f[0].severity, Severity.MEDIUM)

    def test_no_is_clean(self):
        self.assertNotIn("SSH-001", rule_ids(scan_string("PermitRootLogin no\n")))

    def test_forced_commands_only_is_clean(self):
        text = "PermitRootLogin forced-commands-only\n"
        self.assertNotIn("SSH-001", rule_ids(scan_string(text)))


class Ssh002Tests(unittest.TestCase):
    def test_yes_fires_high(self):
        f = scan_string("PasswordAuthentication yes\n")
        self.assertIn("SSH-002", rule_ids(f))

    def test_absent_fires_high(self):
        self.assertIn("SSH-002", rule_ids(scan_string("")))

    def test_no_is_clean(self):
        self.assertNotIn(
            "SSH-002",
            rule_ids(scan_string("PasswordAuthentication no\n")))


class Ssh003Tests(unittest.TestCase):
    def test_yes_fires(self):
        self.assertIn(
            "SSH-003",
            rule_ids(scan_string("PermitEmptyPasswords yes\n")))

    def test_absent_is_clean(self):
        self.assertNotIn("SSH-003", rule_ids(scan_string("")))


class Ssh004Tests(unittest.TestCase):
    def test_protocol_one_fires(self):
        self.assertIn("SSH-004", rule_ids(scan_string("Protocol 2,1\n")))

    def test_protocol_two_only_is_clean(self):
        self.assertNotIn("SSH-004", rule_ids(scan_string("Protocol 2\n")))


class Ssh005Tests(unittest.TestCase):
    def test_x11_yes_fires(self):
        self.assertIn("SSH-005", rule_ids(scan_string("X11Forwarding yes\n")))

    def test_x11_no_is_clean(self):
        self.assertNotIn(
            "SSH-005", rule_ids(scan_string("X11Forwarding no\n")))


class Ssh006Tests(unittest.TestCase):
    def test_six_fires(self):
        self.assertIn("SSH-006", rule_ids(scan_string("MaxAuthTries 6\n")))

    def test_four_is_clean(self):
        self.assertNotIn("SSH-006", rule_ids(scan_string("MaxAuthTries 4\n")))

    def test_absent_fires(self):
        self.assertIn("SSH-006", rule_ids(scan_string("")))

    def test_non_integer_fires(self):
        self.assertIn(
            "SSH-006", rule_ids(scan_string("MaxAuthTries banana\n")))


class Ssh007Tests(unittest.TestCase):
    def test_long_grace_time_fires(self):
        self.assertIn(
            "SSH-007", rule_ids(scan_string("LoginGraceTime 300\n")))

    def test_zero_fires_high(self):
        f = [x for x in scan_string("LoginGraceTime 0\n")
             if x.rule_id == "SSH-007"]
        self.assertTrue(f)
        self.assertEqual(f[0].severity, Severity.HIGH)

    def test_sixty_seconds_is_clean(self):
        self.assertNotIn(
            "SSH-007", rule_ids(scan_string("LoginGraceTime 60\n")))

    def test_time_spec_minutes_parses(self):
        # 1m = 60s = clean
        self.assertNotIn(
            "SSH-007", rule_ids(scan_string("LoginGraceTime 1m\n")))
        # 2m = 120s = fires
        self.assertIn(
            "SSH-007", rule_ids(scan_string("LoginGraceTime 2m\n")))


class Ssh008Tests(unittest.TestCase):
    def test_absent_interval_fires(self):
        self.assertIn("SSH-008", rule_ids(scan_string("")))

    def test_zero_interval_fires(self):
        text = "ClientAliveInterval 0\n"
        self.assertIn("SSH-008", rule_ids(scan_string(text)))

    def test_high_count_fires(self):
        text = (
            "ClientAliveInterval 300\n"
            "ClientAliveCountMax 10\n"
        )
        self.assertIn("SSH-008", rule_ids(scan_string(text)))

    def test_good_values_are_clean(self):
        text = (
            "ClientAliveInterval 300\n"
            "ClientAliveCountMax 3\n"
        )
        self.assertNotIn("SSH-008", rule_ids(scan_string(text)))

    def test_unparseable_interval_fires(self):
        # Parity with SSH-006 / SSH-007: an unparseable value is a
        # posture defect, not silently clean.
        text = (
            "ClientAliveInterval banana\n"
            "ClientAliveCountMax 3\n"
        )
        f = [x for x in scan_string(text) if x.rule_id == "SSH-008"]
        self.assertTrue(f)
        self.assertIn("not a parseable duration", f[0].message)

    def test_unparseable_count_fires(self):
        text = (
            "ClientAliveInterval 300\n"
            "ClientAliveCountMax banana\n"
        )
        f = [x for x in scan_string(text) if x.rule_id == "SSH-008"]
        self.assertTrue(f)
        self.assertIn("not an integer", f[0].message)


class Ssh009Tests(unittest.TestCase):
    def test_hostbased_yes_fires(self):
        self.assertIn(
            "SSH-009",
            rule_ids(scan_string("HostbasedAuthentication yes\n")))

    def test_hostbased_no_is_clean(self):
        self.assertNotIn(
            "SSH-009",
            rule_ids(scan_string("HostbasedAuthentication no\n")))


class Ssh010Tests(unittest.TestCase):
    def test_no_fires(self):
        self.assertIn("SSH-010", rule_ids(scan_string("IgnoreRhosts no\n")))

    def test_absent_fires(self):
        self.assertIn("SSH-010", rule_ids(scan_string("")))

    def test_yes_is_clean(self):
        self.assertNotIn(
            "SSH-010", rule_ids(scan_string("IgnoreRhosts yes\n")))


class Ssh011Tests(unittest.TestCase):
    def test_cbc_cipher_fires_high(self):
        f = [x for x in scan_string("Ciphers aes128-cbc\n")
             if x.rule_id == "SSH-011"]
        self.assertTrue(f)
        self.assertEqual(f[0].severity, Severity.HIGH)

    def test_arcfour_fires(self):
        self.assertIn("SSH-011", rule_ids(scan_string("Ciphers arcfour\n")))

    def test_modern_set_is_clean(self):
        text = (
            "Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com\n"
        )
        self.assertNotIn("SSH-011", rule_ids(scan_string(text)))

    def test_prefix_modifier_is_info_only(self):
        f = [x for x in scan_string("Ciphers -aes128-cbc\n")
             if x.rule_id == "SSH-011"]
        self.assertTrue(f)
        self.assertEqual(f[0].severity, Severity.INFO)


class Ssh012Tests(unittest.TestCase):
    def test_md5_fires_high(self):
        self.assertIn("SSH-012", rule_ids(scan_string("MACs hmac-md5\n")))

    def test_umac64_fires(self):
        self.assertIn(
            "SSH-012",
            rule_ids(scan_string("MACs umac-64@openssh.com\n")))

    def test_modern_set_is_clean(self):
        self.assertNotIn(
            "SSH-012",
            rule_ids(scan_string("MACs hmac-sha2-512-etm@openssh.com\n")))


class Ssh013Tests(unittest.TestCase):
    def test_group1_sha1_fires_high(self):
        self.assertIn(
            "SSH-013",
            rule_ids(scan_string("KexAlgorithms diffie-hellman-group1-sha1\n")))

    def test_curve25519_is_clean(self):
        self.assertNotIn(
            "SSH-013",
            rule_ids(scan_string("KexAlgorithms curve25519-sha256\n")))


class Ssh014Tests(unittest.TestCase):
    """SSH-014 is INFO; it only fires under --strict or --include-info."""

    def test_fires_under_include_info(self):
        text = "LogLevel QUIET\n"
        f = rule_ids(scan_string(text, Options(include_info=True)))
        self.assertIn("SSH-014", f)

    def test_silent_in_default_mode(self):
        text = "LogLevel QUIET\n"
        self.assertNotIn("SSH-014", rule_ids(scan_string(text)))

    def test_info_level_is_clean_even_in_strict(self):
        text = "LogLevel INFO\n"
        self.assertNotIn(
            "SSH-014", rule_ids(scan_string(text, Options(strict=True))))


class Ssh015Tests(unittest.TestCase):
    def test_use_pam_no_fires(self):
        self.assertIn("SSH-015", rule_ids(scan_string("UsePAM no\n")))

    def test_use_pam_yes_is_clean(self):
        self.assertNotIn("SSH-015", rule_ids(scan_string("UsePAM yes\n")))


class RegistryIntegrityTests(unittest.TestCase):
    def test_rule_ids_are_unique(self):
        ids = [r.id for r in REGISTRY]
        self.assertEqual(len(ids), len(set(ids)))

    def test_all_rules_use_ssh_prefix(self):
        for r in REGISTRY:
            self.assertTrue(r.id.startswith("SSH-"))

    def test_first_rule_is_ssh_001(self):
        self.assertEqual(REGISTRY[0].id, "SSH-001")

    def test_findings_from_run_all_are_sorted(self):
        text = (
            "PermitRootLogin yes\n"
            "PasswordAuthentication yes\n"
            "MaxAuthTries 10\n"
        )
        directives = parse_text(text)
        findings = run_all(
            directives, text, "fx", Options(include_info=True))
        for a, b in zip(findings, findings[1:]):
            self.assertLessEqual(
                (a.path, a.line, a.rule_id),
                (b.path, b.line, b.rule_id),
            )


class DisableAndOnlyTests(unittest.TestCase):
    def test_disable_suppresses_a_rule(self):
        text = "PermitRootLogin yes\nPasswordAuthentication yes\n"
        f = scan_string(text, Options(disabled=("SSH-001",)))
        self.assertNotIn("SSH-001", rule_ids(f))
        self.assertIn("SSH-002", rule_ids(f))

    def test_only_restricts_to_a_rule(self):
        text = "PermitRootLogin yes\nPasswordAuthentication yes\n"
        f = scan_string(text, Options(only=("SSH-002",)))
        self.assertEqual(set(rule_ids(f)), {"SSH-002"})


if __name__ == "__main__":
    unittest.main()
