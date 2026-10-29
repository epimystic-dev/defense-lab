"""Dockerfile parser tests."""

from __future__ import annotations

import unittest

from tests import support  # noqa: F401

from composecheck.parse_dockerfile import (
    Instruction,
    by_keyword,
    parse_dockerfile,
)


class ParseBasicsTests(unittest.TestCase):
    def test_blank_and_comments_ignored(self):
        text = (
            "# a comment\n"
            "\n"
            "FROM alpine\n"
        )
        inst = parse_dockerfile(text)
        self.assertEqual(len(inst), 1)
        self.assertEqual(inst[0].keyword, "FROM")
        self.assertEqual(inst[0].args, "alpine")

    def test_case_folded_keyword(self):
        inst = parse_dockerfile("from alpine\nUser root\n")
        self.assertEqual([i.keyword for i in inst], ["FROM", "USER"])

    def test_line_continuation(self):
        text = (
            "RUN apt-get update \\\n"
            "    && apt-get install -y curl \\\n"
            "    && rm -rf /var/lib/apt/lists/*\n"
        )
        inst = parse_dockerfile(text)
        self.assertEqual(len(inst), 1)
        self.assertIn("apt-get install", inst[0].args)
        self.assertIn("/var/lib/apt/lists", inst[0].args)

    def test_line_number_is_first_physical_line(self):
        text = (
            "# header\n"
            "FROM alpine\n"
            "RUN echo hi\n"
        )
        inst = parse_dockerfile(text)
        self.assertEqual(inst[0].line, 2)
        self.assertEqual(inst[1].line, 3)

    def test_by_keyword(self):
        text = (
            "FROM alpine\n"
            "RUN echo one\n"
            "RUN echo two\n"
            "USER app\n"
        )
        inst = parse_dockerfile(text)
        self.assertEqual(len(by_keyword(inst, "RUN")), 2)
        self.assertEqual(len(by_keyword(inst, "run")), 2)


if __name__ == "__main__":
    unittest.main()
