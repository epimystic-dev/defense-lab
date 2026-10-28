"""DKIM rule tests (DKIM-001..DKIM-008)."""

from __future__ import annotations

import unittest

from tests import support  # noqa: F401
from tests.support import (
    make_rsa_spki_base64,
    rule_ids,
    scan_zone_string,
)

from dnsrec.types import Options


def _ids(text, options=None):
    return rule_ids(scan_zone_string(text, options))


class DKIM001WrongVersionTests(unittest.TestCase):
    def test_v_dkim2_fires(self):
        text = (
            "$ORIGIN example.invalid.\n"
            "sel._domainkey  IN TXT \"v=DKIM2; k=rsa; p=aGVsbG8=\"\n"
        )
        self.assertIn("DKIM-001", _ids(text))

    def test_v_dkim1_clean(self):
        text = (
            "$ORIGIN example.invalid.\n"
            "sel._domainkey  IN TXT \"v=DKIM1; k=rsa; p=aGVsbG8=\"\n"
        )
        self.assertNotIn("DKIM-001", _ids(text))

    def test_v_absent_clean(self):
        # RFC 6376: v= tag MAY be absent; the default is DKIM1.
        text = (
            "$ORIGIN example.invalid.\n"
            "sel._domainkey  IN TXT \"k=rsa; p=aGVsbG8=\"\n"
        )
        self.assertNotIn("DKIM-001", _ids(text))


class DKIM002BadKTests(unittest.TestCase):
    def test_unknown_k_fires(self):
        text = (
            "$ORIGIN example.invalid.\n"
            "sel._domainkey  IN TXT \"v=DKIM1; k=weirdalgo; p=aGVsbG8=\"\n"
        )
        self.assertIn("DKIM-002", _ids(text))

    def test_rsa_clean(self):
        text = (
            "$ORIGIN example.invalid.\n"
            "sel._domainkey  IN TXT \"v=DKIM1; k=rsa; p=aGVsbG8=\"\n"
        )
        self.assertNotIn("DKIM-002", _ids(text))

    def test_ed25519_clean(self):
        text = (
            "$ORIGIN example.invalid.\n"
            "sel._domainkey  IN TXT \"v=DKIM1; k=ed25519; p=aGVsbG8=\"\n"
        )
        self.assertNotIn("DKIM-002", _ids(text))


class DKIM003EmptyPTests(unittest.TestCase):
    def test_empty_p_fires(self):
        text = (
            "$ORIGIN example.invalid.\n"
            "sel._domainkey  IN TXT \"v=DKIM1; k=rsa; p=\"\n"
        )
        self.assertIn("DKIM-003", _ids(text))

    def test_p_missing_clean(self):
        # DKIM-003 is specifically the empty-p= (revocation) rule and
        # does not fire when p= is absent entirely. The absent-p= case
        # is covered by DKIM-009 (see DKIM009MissingPTests).
        text = (
            "$ORIGIN example.invalid.\n"
            "sel._domainkey  IN TXT \"v=DKIM1; k=rsa\"\n"
        )
        self.assertNotIn("DKIM-003", _ids(text))


class DKIM009MissingPTests(unittest.TestCase):
    def test_missing_p_fires(self):
        # RFC 6376 section 3.6.1 marks p= as REQUIRED. A record whose
        # p= tag is absent entirely has no public key available at the
        # selector; receivers cannot verify any signature from the
        # selector and treat the signed mail as unsigned. Prior to
        # DKIM-009 this record passed with ZERO findings - a materially
        # wrong clean verdict. The regression test fixture is the one
        # that previously demonstrated the gap.
        text = (
            "$ORIGIN example.invalid.\n"
            "sel._domainkey  IN TXT \"v=DKIM1; k=rsa\"\n"
        )
        self.assertIn("DKIM-009", _ids(text))

    def test_p_present_clean(self):
        text = (
            "$ORIGIN example.invalid.\n"
            "sel._domainkey  IN TXT \"v=DKIM1; k=rsa; p=aGVsbG8=\"\n"
        )
        self.assertNotIn("DKIM-009", _ids(text))

    def test_empty_p_clean_for_dkim_009(self):
        # An empty p= is explicit revocation (DKIM-003), not a missing
        # tag; DKIM-009 must NOT fire on the revocation shape so the
        # two rules stay disjoint.
        text = (
            "$ORIGIN example.invalid.\n"
            "sel._domainkey  IN TXT \"v=DKIM1; k=rsa; p=\"\n"
        )
        ids = _ids(text)
        self.assertIn("DKIM-003", ids)
        self.assertNotIn("DKIM-009", ids)

    def test_fires_without_v_tag(self):
        # v= is optional per RFC 6376 (defaults to DKIM1). A record
        # with no v= and no p= is still missing the required key.
        text = (
            "$ORIGIN example.invalid.\n"
            "sel._domainkey  IN TXT \"k=rsa\"\n"
        )
        self.assertIn("DKIM-009", _ids(text))


class DKIM004SmallKeyTests(unittest.TestCase):
    def test_1024_bit_key_fires(self):
        p = make_rsa_spki_base64(1024)
        text = (
            "$ORIGIN example.invalid.\n"
            "sel._domainkey  IN TXT \"v=DKIM1; k=rsa; p=" + p + "\"\n"
        )
        self.assertIn("DKIM-004", _ids(text))

    def test_2048_bit_key_clean(self):
        p = make_rsa_spki_base64(2048)
        text = (
            "$ORIGIN example.invalid.\n"
            "sel._domainkey  IN TXT \"v=DKIM1; k=rsa; p=" + p + "\"\n"
        )
        self.assertNotIn("DKIM-004", _ids(text))

    def test_ed25519_skipped(self):
        text = (
            "$ORIGIN example.invalid.\n"
            "sel._domainkey  IN TXT \"v=DKIM1; k=ed25519; p=aGVsbG8=\"\n"
        )
        self.assertNotIn("DKIM-004", _ids(text))


class DKIM005TestingTests(unittest.TestCase):
    def test_t_y_fires(self):
        text = (
            "$ORIGIN example.invalid.\n"
            "sel._domainkey  IN TXT \"v=DKIM1; k=rsa; t=y; p=aGVsbG8=\"\n"
        )
        self.assertIn("DKIM-005", _ids(text))

    def test_t_s_clean(self):
        text = (
            "$ORIGIN example.invalid.\n"
            "sel._domainkey  IN TXT \"v=DKIM1; k=rsa; t=s; p=aGVsbG8=\"\n"
        )
        self.assertNotIn("DKIM-005", _ids(text))

    def test_t_y_s_fires(self):
        # The t= tag is colon-separated flags; y plus any other flag
        # still means testing.
        text = (
            "$ORIGIN example.invalid.\n"
            "sel._domainkey  IN TXT \"v=DKIM1; k=rsa; t=y:s; p=aGVsbG8=\"\n"
        )
        self.assertIn("DKIM-005", _ids(text))


class DKIM006GTagTests(unittest.TestCase):
    def test_g_tag_fires_with_strict(self):
        text = (
            "$ORIGIN example.invalid.\n"
            "sel._domainkey  IN TXT \"v=DKIM1; k=rsa; g=*; p=aGVsbG8=\"\n"
        )
        self.assertIn("DKIM-006", _ids(text, Options(strict=True)))


class DKIM007BadBase64Tests(unittest.TestCase):
    def test_non_base64_characters_fire(self):
        text = (
            "$ORIGIN example.invalid.\n"
            "sel._domainkey  IN TXT \"v=DKIM1; k=rsa; p=not_base64!@#$\"\n"
        )
        self.assertIn("DKIM-007", _ids(text))

    def test_valid_base64_clean(self):
        text = (
            "$ORIGIN example.invalid.\n"
            "sel._domainkey  IN TXT \"v=DKIM1; k=rsa; p=aGVsbG8=\"\n"
        )
        self.assertNotIn("DKIM-007", _ids(text))


class DKIM008WrongOwnerTests(unittest.TestCase):
    def test_wrong_owner_fires(self):
        text = (
            "$ORIGIN example.invalid.\n"
            "wrong  IN TXT \"v=DKIM1; k=rsa; p=aGVsbG8=\"\n"
        )
        self.assertIn("DKIM-008", _ids(text))

    def test_correct_owner_clean(self):
        text = (
            "$ORIGIN example.invalid.\n"
            "sel._domainkey  IN TXT \"v=DKIM1; k=rsa; p=aGVsbG8=\"\n"
        )
        self.assertNotIn("DKIM-008", _ids(text))


if __name__ == "__main__":
    unittest.main()
