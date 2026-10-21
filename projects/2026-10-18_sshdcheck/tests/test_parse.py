"""Parser-level tests for sshdcheck."""

from __future__ import annotations

import unittest

from sshdcheck.parse import (
    canonical_keyword,
    effective_global,
    first_global,
    index_by_keyword,
    parse_text,
    split_csv_or_space,
    value_truthy,
)


class CanonicalKeywordTests(unittest.TestCase):
    def test_known_keywords_fold_to_their_sshd_config_spelling(self):
        self.assertEqual(canonical_keyword("permitrootlogin"), "PermitRootLogin")
        self.assertEqual(canonical_keyword("PERMITROOTLOGIN"), "PermitRootLogin")
        self.assertEqual(canonical_keyword("macs"), "MACs")
        self.assertEqual(canonical_keyword("kexalgorithms"), "KexAlgorithms")

    def test_unknown_keyword_passes_through(self):
        self.assertEqual(canonical_keyword("InvisibleThing"), "InvisibleThing")


class ParseTextTests(unittest.TestCase):
    def test_strips_blank_lines_and_comments(self):
        text = "\n# a comment\n\nPort 22\n"
        directives = parse_text(text)
        self.assertEqual(len(directives), 1)
        self.assertEqual(directives[0].keyword, "Port")
        self.assertEqual(directives[0].value, "22")

    def test_records_physical_line_numbers(self):
        text = "\n\nPermitRootLogin no\n"
        directives = parse_text(text)
        self.assertEqual(directives[0].line, 3)

    def test_multi_word_value_is_preserved(self):
        text = (
            "Ciphers aes256-ctr,aes128-ctr,chacha20-poly1305@openssh.com\n"
        )
        directives = parse_text(text)
        self.assertEqual(directives[0].keyword, "Ciphers")
        self.assertIn("chacha20-poly1305", directives[0].value)

    def test_match_block_marks_following_lines(self):
        text = (
            "PermitRootLogin no\n"
            "Match User admin\n"
            "    AllowTcpForwarding yes\n"
        )
        directives = parse_text(text)
        # Pre-Match directive is global.
        self.assertFalse(directives[0].in_match)
        # The Match directive itself is a marker; downstream rules see
        # it but don't apply global rules to it.
        self.assertEqual(directives[1].keyword, "Match")
        # Everything after Match is scoped to the match block.
        self.assertTrue(directives[2].in_match)

    def test_tabs_and_spaces_are_both_separators(self):
        text = "PermitRootLogin\tno\n"
        directives = parse_text(text)
        self.assertEqual(directives[0].value, "no")


class IndexByKeywordTests(unittest.TestCase):
    def test_first_and_effective_global_differ_when_overridden(self):
        text = (
            "PermitRootLogin yes\n"
            "PermitRootLogin no\n"
        )
        directives = parse_text(text)
        idx = index_by_keyword(directives)
        self.assertEqual(first_global(idx, "PermitRootLogin").value, "yes")
        self.assertEqual(
            effective_global(idx, "PermitRootLogin").value, "no")

    def test_match_scoped_entries_do_not_count_as_global(self):
        text = (
            "Match User admin\n"
            "    AllowTcpForwarding yes\n"
        )
        directives = parse_text(text)
        idx = index_by_keyword(directives)
        self.assertIsNone(effective_global(idx, "AllowTcpForwarding"))


class CsvOrSpaceTests(unittest.TestCase):
    def test_commas(self):
        self.assertEqual(
            split_csv_or_space("a,b,c"), ["a", "b", "c"])

    def test_whitespace(self):
        self.assertEqual(
            split_csv_or_space("a   b\tc"), ["a", "b", "c"])

    def test_mixed(self):
        self.assertEqual(
            split_csv_or_space("a, b ,c"), ["a", "b", "c"])


class ValueTruthyTests(unittest.TestCase):
    def test_yes_no(self):
        self.assertIs(value_truthy("yes"), True)
        self.assertIs(value_truthy("YES"), True)
        self.assertIs(value_truthy("no"), False)
        self.assertIs(value_truthy("No"), False)

    def test_unknown_returns_none(self):
        self.assertIsNone(value_truthy("prohibit-password"))
        self.assertIsNone(value_truthy(""))


if __name__ == "__main__":
    unittest.main()
