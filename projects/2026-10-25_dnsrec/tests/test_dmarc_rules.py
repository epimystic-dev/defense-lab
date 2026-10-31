"""DMARC rule tests (DMARC-001..DMARC-010)."""

from __future__ import annotations

import unittest

from tests import support  # noqa: F401
from tests.support import rule_ids, scan_zone_string


def _ids(text):
    return rule_ids(scan_zone_string(text))


class DMARC001PNoneTests(unittest.TestCase):
    def test_p_none_fires(self):
        text = (
            "$ORIGIN example.invalid.\n"
            "_dmarc  IN TXT \"v=DMARC1; p=none; rua=mailto:a@example.invalid; adkim=s; aspf=s\"\n"
        )
        self.assertIn("DMARC-001", _ids(text))

    def test_p_reject_clean(self):
        text = (
            "$ORIGIN example.invalid.\n"
            "_dmarc  IN TXT \"v=DMARC1; p=reject; rua=mailto:a@example.invalid; adkim=s; aspf=s\"\n"
        )
        self.assertNotIn("DMARC-001", _ids(text))


class DMARC002PQuarantineTests(unittest.TestCase):
    def test_p_quarantine_fires(self):
        text = (
            "$ORIGIN example.invalid.\n"
            "_dmarc  IN TXT \"v=DMARC1; p=quarantine; rua=mailto:a@example.invalid; adkim=s; aspf=s\"\n"
        )
        self.assertIn("DMARC-002", _ids(text))


class DMARC003MissingPTests(unittest.TestCase):
    def test_missing_p_fires(self):
        text = (
            "$ORIGIN example.invalid.\n"
            "_dmarc  IN TXT \"v=DMARC1; rua=mailto:a@example.invalid; adkim=s; aspf=s\"\n"
        )
        self.assertIn("DMARC-003", _ids(text))

    def test_missing_v_does_not_double_report(self):
        text = (
            "$ORIGIN example.invalid.\n"
            "_dmarc  IN TXT \"p=none\"\n"
        )
        # DMARC-004 fires (bad version), DMARC-003 does not (to avoid
        # double-reporting a record that is already flagged on the
        # version level).
        ids = _ids(text)
        self.assertIn("DMARC-004", ids)
        self.assertNotIn("DMARC-003", ids)


class DMARC004WrongVersionTests(unittest.TestCase):
    def test_v_dmarc2_fires(self):
        text = (
            "$ORIGIN example.invalid.\n"
            "_dmarc  IN TXT \"v=DMARC2; p=reject; rua=mailto:a@example.invalid; adkim=s; aspf=s\"\n"
        )
        self.assertIn("DMARC-004", _ids(text))


class DMARC005PctTests(unittest.TestCase):
    def test_pct_50_fires(self):
        text = (
            "$ORIGIN example.invalid.\n"
            "_dmarc  IN TXT \"v=DMARC1; p=reject; pct=50; rua=mailto:a@example.invalid; adkim=s; aspf=s\"\n"
        )
        self.assertIn("DMARC-005", _ids(text))

    def test_pct_100_clean(self):
        text = (
            "$ORIGIN example.invalid.\n"
            "_dmarc  IN TXT \"v=DMARC1; p=reject; pct=100; rua=mailto:a@example.invalid; adkim=s; aspf=s\"\n"
        )
        self.assertNotIn("DMARC-005", _ids(text))

    def test_pct_absent_clean(self):
        text = (
            "$ORIGIN example.invalid.\n"
            "_dmarc  IN TXT \"v=DMARC1; p=reject; rua=mailto:a@example.invalid; adkim=s; aspf=s\"\n"
        )
        self.assertNotIn("DMARC-005", _ids(text))

    def test_pct_non_integer_fires(self):
        # RFC 7489 section 6.3 requires pct to be a plain-text integer.
        # A non-integer value (operator typo, zone-editor artefact) is
        # ignored by receivers and silently defaults to pct=100, so the
        # operator's intended partial rollout is lost. Previously the
        # rule caught ValueError and returned silently clean.
        text = (
            "$ORIGIN example.invalid.\n"
            "_dmarc  IN TXT \"v=DMARC1; p=reject; pct=banana; rua=mailto:a@example.invalid; adkim=s; aspf=s\"\n"
        )
        self.assertIn("DMARC-005", _ids(text))

    def test_pct_above_100_fires(self):
        # Out-of-range pct is a shape defect: receivers ignore the tag.
        text = (
            "$ORIGIN example.invalid.\n"
            "_dmarc  IN TXT \"v=DMARC1; p=reject; pct=150; rua=mailto:a@example.invalid; adkim=s; aspf=s\"\n"
        )
        self.assertIn("DMARC-005", _ids(text))

    def test_pct_negative_fires(self):
        # Negative pct is also out-of-range per RFC 7489 section 6.3.
        text = (
            "$ORIGIN example.invalid.\n"
            "_dmarc  IN TXT \"v=DMARC1; p=reject; pct=-5; rua=mailto:a@example.invalid; adkim=s; aspf=s\"\n"
        )
        self.assertIn("DMARC-005", _ids(text))

    def test_pct_zero_fires(self):
        # pct=0 is in-range but still a partial-deployment posture
        # (nothing is enforced); the existing partial-deployment branch
        # covers it. Pin that branch so a future refactor cannot drop it.
        text = (
            "$ORIGIN example.invalid.\n"
            "_dmarc  IN TXT \"v=DMARC1; p=reject; pct=0; rua=mailto:a@example.invalid; adkim=s; aspf=s\"\n"
        )
        self.assertIn("DMARC-005", _ids(text))


class DMARC006AdkimTests(unittest.TestCase):
    def test_adkim_r_fires(self):
        text = (
            "$ORIGIN example.invalid.\n"
            "_dmarc  IN TXT \"v=DMARC1; p=reject; adkim=r; aspf=s; rua=mailto:a@example.invalid\"\n"
        )
        self.assertIn("DMARC-006", _ids(text))

    def test_default_adkim_r_fires(self):
        text = (
            "$ORIGIN example.invalid.\n"
            "_dmarc  IN TXT \"v=DMARC1; p=reject; aspf=s; rua=mailto:a@example.invalid\"\n"
        )
        self.assertIn("DMARC-006", _ids(text))


class DMARC007AspfTests(unittest.TestCase):
    def test_aspf_r_fires(self):
        text = (
            "$ORIGIN example.invalid.\n"
            "_dmarc  IN TXT \"v=DMARC1; p=reject; adkim=s; aspf=r; rua=mailto:a@example.invalid\"\n"
        )
        self.assertIn("DMARC-007", _ids(text))


class DMARC008MissingRuaTests(unittest.TestCase):
    def test_no_rua_fires(self):
        text = (
            "$ORIGIN example.invalid.\n"
            "_dmarc  IN TXT \"v=DMARC1; p=reject; adkim=s; aspf=s\"\n"
        )
        self.assertIn("DMARC-008", _ids(text))

    def test_rua_present_clean(self):
        text = (
            "$ORIGIN example.invalid.\n"
            "_dmarc  IN TXT \"v=DMARC1; p=reject; adkim=s; aspf=s; rua=mailto:a@example.invalid\"\n"
        )
        self.assertNotIn("DMARC-008", _ids(text))


class DMARC009SpWeakerTests(unittest.TestCase):
    def test_sp_weaker_fires(self):
        text = (
            "$ORIGIN example.invalid.\n"
            "_dmarc  IN TXT \"v=DMARC1; p=reject; sp=none; adkim=s; aspf=s; rua=mailto:a@example.invalid\"\n"
        )
        self.assertIn("DMARC-009", _ids(text))

    def test_sp_equal_clean(self):
        text = (
            "$ORIGIN example.invalid.\n"
            "_dmarc  IN TXT \"v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s; rua=mailto:a@example.invalid\"\n"
        )
        self.assertNotIn("DMARC-009", _ids(text))


class DMARC010WrongOwnerTests(unittest.TestCase):
    def test_wrong_owner_fires(self):
        text = (
            "$ORIGIN example.invalid.\n"
            "wrong  IN TXT \"v=DMARC1; p=reject; adkim=s; aspf=s; rua=mailto:a@example.invalid\"\n"
        )
        self.assertIn("DMARC-010", _ids(text))

    def test_correct_owner_clean(self):
        text = (
            "$ORIGIN example.invalid.\n"
            "_dmarc  IN TXT \"v=DMARC1; p=reject; adkim=s; aspf=s; rua=mailto:a@example.invalid\"\n"
        )
        self.assertNotIn("DMARC-010", _ids(text))


class DMARC011InvalidPolicyValueTests(unittest.TestCase):
    # RFC 7489 section 6.3 fixes p= to one of none, quarantine, reject;
    # section 6.6.3 states a receiver that cannot parse p= MUST NOT
    # apply the DMARC mechanism. Pre-DMARC-011, a typo on p= passed
    # entirely clean, so the operator believed a reject policy was in
    # force when every receiver was actually skipping DMARC.

    def test_p_rejects_typo_fires(self):
        # The exact pre-fix reproducer: `rejects` is a very plausible
        # typo for `reject`.
        text = (
            "$ORIGIN example.invalid.\n"
            "_dmarc  IN TXT \"v=DMARC1; p=rejects; rua=mailto:a@example.invalid; adkim=s; aspf=s\"\n"
        )
        self.assertIn("DMARC-011", _ids(text))

    def test_p_arbitrary_value_fires(self):
        text = (
            "$ORIGIN example.invalid.\n"
            "_dmarc  IN TXT \"v=DMARC1; p=banana; rua=mailto:a@example.invalid; adkim=s; aspf=s\"\n"
        )
        self.assertIn("DMARC-011", _ids(text))

    def test_p_reject_uppercase_clean(self):
        # Section 6.6.3 requires case-insensitive parsing of tag values.
        text = (
            "$ORIGIN example.invalid.\n"
            "_dmarc  IN TXT \"v=DMARC1; p=REJECT; rua=mailto:a@example.invalid; adkim=s; aspf=s\"\n"
        )
        self.assertNotIn("DMARC-011", _ids(text))

    def test_p_reject_clean(self):
        text = (
            "$ORIGIN example.invalid.\n"
            "_dmarc  IN TXT \"v=DMARC1; p=reject; rua=mailto:a@example.invalid; adkim=s; aspf=s\"\n"
        )
        self.assertNotIn("DMARC-011", _ids(text))

    def test_p_none_disjoint_from_dmarc_011(self):
        # p=none is a valid-but-weak policy. DMARC-001 owns that case;
        # DMARC-011 must not double-report it.
        text = (
            "$ORIGIN example.invalid.\n"
            "_dmarc  IN TXT \"v=DMARC1; p=none; rua=mailto:a@example.invalid; adkim=s; aspf=s\"\n"
        )
        ids = _ids(text)
        self.assertIn("DMARC-001", ids)
        self.assertNotIn("DMARC-011", ids)

    def test_p_quarantine_disjoint_from_dmarc_011(self):
        # p=quarantine is DMARC-002's territory.
        text = (
            "$ORIGIN example.invalid.\n"
            "_dmarc  IN TXT \"v=DMARC1; p=quarantine; rua=mailto:a@example.invalid; adkim=s; aspf=s\"\n"
        )
        ids = _ids(text)
        self.assertIn("DMARC-002", ids)
        self.assertNotIn("DMARC-011", ids)

    def test_missing_p_disjoint_from_dmarc_011(self):
        # DMARC-003 handles the missing-p= case; DMARC-011 only fires
        # when a value is present but invalid.
        text = (
            "$ORIGIN example.invalid.\n"
            "_dmarc  IN TXT \"v=DMARC1; rua=mailto:a@example.invalid; adkim=s; aspf=s\"\n"
        )
        ids = _ids(text)
        self.assertIn("DMARC-003", ids)
        self.assertNotIn("DMARC-011", ids)

    def test_wrong_version_disjoint_from_dmarc_011(self):
        # DMARC-004 handles the wrong-version case; DMARC-011 is gated
        # off until the version section is intact so a single defect is
        # reported once.
        text = (
            "$ORIGIN example.invalid.\n"
            "_dmarc  IN TXT \"v=DMARC2; p=banana; rua=mailto:a@example.invalid; adkim=s; aspf=s\"\n"
        )
        ids = _ids(text)
        self.assertIn("DMARC-004", ids)
        self.assertNotIn("DMARC-011", ids)


if __name__ == "__main__":
    unittest.main()
