"""Parser tests - BIND zone-file shape and bare-record shape."""

from __future__ import annotations

import unittest

from tests import support  # noqa: F401

from dnsrec.parse import parse_bare_text, parse_zone_text
from dnsrec.types import RecordKind


class ZoneParserTests(unittest.TestCase):
    def test_single_spf_record(self):
        text = (
            "$ORIGIN example.invalid.\n"
            "@  IN TXT \"v=spf1 -all\"\n"
        )
        records = parse_zone_text(text)
        self.assertEqual(len(records), 1)
        self.assertIs(records[0].kind, RecordKind.SPF)
        self.assertEqual(records[0].owner, "example.invalid")
        self.assertEqual(records[0].value, "v=spf1 -all")

    def test_dmarc_owner_classification(self):
        text = (
            "$ORIGIN example.invalid.\n"
            "_dmarc  IN TXT \"v=DMARC1; p=reject\"\n"
        )
        records = parse_zone_text(text)
        self.assertEqual(len(records), 1)
        self.assertIs(records[0].kind, RecordKind.DMARC)
        self.assertEqual(records[0].owner, "_dmarc.example.invalid")

    def test_dkim_owner_classification(self):
        text = (
            "$ORIGIN example.invalid.\n"
            "sel._domainkey  IN TXT \"v=DKIM1; k=rsa; p=xyz\"\n"
        )
        records = parse_zone_text(text)
        self.assertEqual(len(records), 1)
        self.assertIs(records[0].kind, RecordKind.DKIM)

    def test_comments_and_blank_lines_ignored(self):
        text = (
            "; a comment\n"
            "\n"
            "$ORIGIN example.invalid.\n"
            "@  IN TXT \"v=spf1 -all\"  ; inline comment\n"
        )
        records = parse_zone_text(text)
        self.assertEqual(len(records), 1)
        # The inline comment is stripped from the record body:
        self.assertNotIn(";", records[0].value)

    def test_multi_line_record(self):
        text = (
            "$ORIGIN example.invalid.\n"
            "@  IN TXT ( \"v=spf1 \"\n"
            "            \"include:_spf.example.net \"\n"
            "            \"-all\" )\n"
        )
        records = parse_zone_text(text)
        self.assertEqual(len(records), 1)
        self.assertEqual(
            records[0].value,
            "v=spf1 include:_spf.example.net -all",
        )

    def test_quoted_strings_concatenated(self):
        text = (
            "$ORIGIN example.invalid.\n"
            "sel._domainkey  IN TXT \"v=DKIM1; \" \"k=rsa; p=abc\"\n"
        )
        records = parse_zone_text(text)
        self.assertEqual(len(records), 1)
        self.assertEqual(
            records[0].value, "v=DKIM1; k=rsa; p=abc",
        )

    def test_absolute_owner_preserves_name(self):
        text = (
            "sub.example.invalid.  IN TXT \"v=spf1 -all\"\n"
        )
        records = parse_zone_text(text)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].owner, "sub.example.invalid")

    def test_classifier_catches_v_dmarc2(self):
        # A near-miss on the version is classified by kind so the
        # version rule can fire, rather than being silently dropped as
        # OTHER.
        text = (
            "$ORIGIN example.invalid.\n"
            "sub  IN TXT \"v=DMARC2; p=reject\"\n"
        )
        records = parse_zone_text(text)
        self.assertEqual(len(records), 1)
        self.assertIs(records[0].kind, RecordKind.DMARC)

    def test_semicolon_inside_quoted_string_is_not_a_comment(self):
        text = (
            "$ORIGIN example.invalid.\n"
            "_dmarc  IN TXT \"v=DMARC1; p=reject\"\n"
        )
        records = parse_zone_text(text)
        self.assertEqual(len(records), 1)
        self.assertIn("p=reject", records[0].value)


class BareParserTests(unittest.TestCase):
    def test_bare_spf_lines(self):
        text = (
            "v=spf1 -all\n"
            "v=spf1 include:_spf.example.net -all\n"
        )
        records = parse_bare_text(text, RecordKind.SPF)
        self.assertEqual(len(records), 2)
        for r in records:
            self.assertIs(r.kind, RecordKind.SPF)

    def test_bare_dmarc_strips_surrounding_quotes(self):
        text = (
            "\"v=DMARC1; p=reject\"\n"
        )
        records = parse_bare_text(text, RecordKind.DMARC)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].value, "v=DMARC1; p=reject")

    def test_bare_ignores_blank_and_comments(self):
        text = (
            "# a comment\n"
            "\n"
            "v=spf1 -all\n"
            "; also a comment\n"
        )
        records = parse_bare_text(text, RecordKind.SPF)
        self.assertEqual(len(records), 1)


if __name__ == "__main__":
    unittest.main()
