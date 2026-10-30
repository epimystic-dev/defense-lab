"""SPF rule tests (SPF-001..SPF-009)."""

from __future__ import annotations

import unittest

from tests import support  # noqa: F401
from tests.support import rule_ids, scan_zone_string

from dnsrec.types import Options


def _ids(text, options=None):
    return rule_ids(scan_zone_string(text, options))


class SPF001MultipleRecordsTests(unittest.TestCase):
    def test_fires_on_two_spf_records_at_same_owner(self):
        text = (
            "$ORIGIN example.invalid.\n"
            "@  IN TXT \"v=spf1 -all\"\n"
            "@  IN TXT \"v=spf1 include:_spf.example.net -all\"\n"
        )
        self.assertIn("SPF-001", _ids(text))

    def test_single_record_clean(self):
        text = "$ORIGIN example.invalid.\n@  IN TXT \"v=spf1 -all\"\n"
        self.assertNotIn("SPF-001", _ids(text))


class SPF002LookupBudgetTests(unittest.TestCase):
    def test_eleven_includes_fires(self):
        includes = " ".join(
            "include:x" + str(i) + ".example.invalid" for i in range(11))
        text = (
            "$ORIGIN example.invalid.\n"
            "@  IN TXT \"v=spf1 " + includes + " -all\"\n"
        )
        self.assertIn("SPF-002", _ids(text))

    def test_ten_includes_clean(self):
        includes = " ".join(
            "include:x" + str(i) + ".example.invalid" for i in range(10))
        text = (
            "$ORIGIN example.invalid.\n"
            "@  IN TXT \"v=spf1 " + includes + " -all\"\n"
        )
        self.assertNotIn("SPF-002", _ids(text))

    def test_a_mx_count(self):
        # a and mx each count; combined with include they can exceed
        # the ten-cap even without eleven includes.
        text = (
            "$ORIGIN example.invalid.\n"
            "@  IN TXT \"v=spf1 "
            + "a mx ptr include:a.example.invalid include:b.example.invalid "
            + "include:c.example.invalid include:d.example.invalid "
            + "include:e.example.invalid include:f.example.invalid "
            + "include:g.example.invalid include:h.example.invalid"
            + " -all\"\n"
        )
        self.assertIn("SPF-002", _ids(text))


class SPF003PermissiveDefaultTests(unittest.TestCase):
    def test_plus_all_fires(self):
        text = (
            "$ORIGIN example.invalid.\n"
            "@  IN TXT \"v=spf1 +all\"\n"
        )
        self.assertIn("SPF-003", _ids(text))

    def test_question_all_fires(self):
        text = (
            "$ORIGIN example.invalid.\n"
            "@  IN TXT \"v=spf1 ?all\"\n"
        )
        self.assertIn("SPF-003", _ids(text))

    def test_hard_fail_clean(self):
        text = (
            "$ORIGIN example.invalid.\n"
            "@  IN TXT \"v=spf1 -all\"\n"
        )
        self.assertNotIn("SPF-003", _ids(text))


class SPF004SoftFailTests(unittest.TestCase):
    def test_tilde_all_fires(self):
        text = (
            "$ORIGIN example.invalid.\n"
            "@  IN TXT \"v=spf1 ~all\"\n"
        )
        self.assertIn("SPF-004", _ids(text))


class SPF005NoAllTests(unittest.TestCase):
    def test_missing_all_fires(self):
        text = (
            "$ORIGIN example.invalid.\n"
            "@  IN TXT \"v=spf1 include:_spf.example.net\"\n"
        )
        self.assertIn("SPF-005", _ids(text))

    def test_redirect_absolves(self):
        text = (
            "$ORIGIN example.invalid.\n"
            "@  IN TXT \"v=spf1 redirect=_spf.example.net\"\n"
        )
        self.assertNotIn("SPF-005", _ids(text))


class SPF006PtrTests(unittest.TestCase):
    def test_ptr_fires(self):
        text = (
            "$ORIGIN example.invalid.\n"
            "@  IN TXT \"v=spf1 ptr -all\"\n"
        )
        self.assertIn("SPF-006", _ids(text))

    def test_qualified_ptr_fires(self):
        text = (
            "$ORIGIN example.invalid.\n"
            "@  IN TXT \"v=spf1 +ptr:example.invalid -all\"\n"
        )
        self.assertIn("SPF-006", _ids(text))


class SPF007LongTests(unittest.TestCase):
    def test_long_body_fires_with_strict(self):
        includes = " ".join(
            "include:x" + str(i) + ".verylongexampledomain.invalid"
            for i in range(10))
        text = (
            "$ORIGIN example.invalid.\n"
            "@  IN TXT \"v=spf1 " + includes + " -all\"\n"
        )
        self.assertIn("SPF-007", _ids(text, Options(strict=True)))

    def test_short_body_does_not_fire(self):
        text = (
            "$ORIGIN example.invalid.\n"
            "@  IN TXT \"v=spf1 -all\"\n"
        )
        self.assertNotIn("SPF-007", _ids(text, Options(strict=True)))


class SPF008WrongVersionTests(unittest.TestCase):
    def test_spf2_fires(self):
        text = (
            "$ORIGIN example.invalid.\n"
            "@  IN TXT \"v=spf2 -all\"\n"
        )
        self.assertIn("SPF-008", _ids(text))


class SPF009WildcardTests(unittest.TestCase):
    def test_ip4_wildcard_fires(self):
        text = (
            "$ORIGIN example.invalid.\n"
            "@  IN TXT \"v=spf1 ip4:0.0.0.0/0 -all\"\n"
        )
        self.assertIn("SPF-009", _ids(text))

    def test_ip6_wildcard_fires(self):
        text = (
            "$ORIGIN example.invalid.\n"
            "@  IN TXT \"v=spf1 ip6:::/0 -all\"\n"
        )
        self.assertIn("SPF-009", _ids(text))

    def test_specific_range_clean(self):
        text = (
            "$ORIGIN example.invalid.\n"
            "@  IN TXT \"v=spf1 ip4:192.0.2.0/24 -all\"\n"
        )
        self.assertNotIn("SPF-009", _ids(text))


class SPF010VersionDelimiterTests(unittest.TestCase):
    # RFC 7208 Appendix A ABNF: record = version terms *SP, with
    # terms = *( 1*SP ( directive / modifier ) ). The version section
    # must be either the entire body or followed by whitespace before
    # the first term; v=spf1-all and v=spf1include:... are discarded
    # by receivers and today pass dnsrec clean or with a misleading
    # SPF-005 "no all mechanism" finding.

    def test_v_spf1_dash_all_fires(self):
        # The dropped-space-before--all case. Today the operator sees
        # SPF-005 and imagines they need to add -all even though they
        # already wrote it; SPF-010 names the real defect.
        text = (
            "$ORIGIN example.invalid.\n"
            "@  IN TXT \"v=spf1-all\"\n"
        )
        self.assertIn("SPF-010", _ids(text))

    def test_v_spf1_include_no_space_fires(self):
        # The silently-clean case before this rule: with -all present
        # SPF-005 does not fire, so the operator sees ZERO findings
        # against a record every receiver will discard. Pin the exact
        # pre-fix behaviour here so a regression is impossible.
        text = (
            "$ORIGIN example.invalid.\n"
            "@  IN TXT \"v=spf1include:_spf.example.net -all\"\n"
        )
        ids = _ids(text)
        self.assertIn("SPF-010", ids)

    def test_tab_after_v_spf1_clean(self):
        # HTAB (0x09) is explicit in the ABNF LWSP definition and
        # does appear in zone-file exports; it must not trigger
        # SPF-010.
        text = (
            "$ORIGIN example.invalid.\n"
            "@  IN TXT \"v=spf1\t-all\"\n"
        )
        self.assertNotIn("SPF-010", _ids(text))

    def test_v_spf1_alone_clean(self):
        # The ABNF permits an empty terms list; v=spf1 is a valid
        # (if neutral) record. Pin that this does not false-fire.
        text = (
            "$ORIGIN example.invalid.\n"
            "@  IN TXT \"v=spf1\"\n"
        )
        self.assertNotIn("SPF-010", _ids(text))

    def test_proper_space_clean(self):
        # Baseline well-formed record must not fire.
        text = (
            "$ORIGIN example.invalid.\n"
            "@  IN TXT \"v=spf1 -all\"\n"
        )
        self.assertNotIn("SPF-010", _ids(text))

    def test_wrong_version_defers_to_spf_008(self):
        # SPF-008 handles the wrong-version case; SPF-010 must not
        # also fire on v=spf2-foo (that would be double-reporting).
        text = (
            "$ORIGIN example.invalid.\n"
            "@  IN TXT \"v=spf2-all\"\n"
        )
        ids = _ids(text)
        self.assertIn("SPF-008", ids)
        self.assertNotIn("SPF-010", ids)


if __name__ == "__main__":
    unittest.main()
