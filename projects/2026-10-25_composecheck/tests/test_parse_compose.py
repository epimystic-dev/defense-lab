"""Compose parser tests."""

from __future__ import annotations

import unittest

from tests import support  # noqa: F401

from composecheck.parse_compose import Scalar, parse_compose


COMPOSE_BASIC = """\
version: "3.8"

services:
  web:
    image: nginx:1.25
    privileged: true
    ports:
      - "8080:80"
    environment:
      - LOG_LEVEL=info
      - PORT=8080
"""


class ParseBasicsTests(unittest.TestCase):
    def test_version_captured(self):
        tree = parse_compose(COMPOSE_BASIC)
        version = tree.root.get("version")
        self.assertIsInstance(version, Scalar)
        self.assertEqual(version.value, "3.8")

    def test_services_block(self):
        tree = parse_compose(COMPOSE_BASIC)
        self.assertEqual(len(tree.services), 1)
        self.assertEqual(tree.services[0].name, "web")

    def test_scalar_value_captured(self):
        tree = parse_compose(COMPOSE_BASIC)
        svc = tree.services[0]
        img = svc.scalar("image")
        self.assertIsNotNone(img)
        self.assertEqual(img.value, "nginx:1.25")

    def test_privileged_captured_as_scalar(self):
        tree = parse_compose(COMPOSE_BASIC)
        svc = tree.services[0]
        s = svc.scalar("privileged")
        self.assertIsNotNone(s)
        self.assertEqual(s.value, "true")

    def test_list_captured(self):
        tree = parse_compose(COMPOSE_BASIC)
        svc = tree.services[0]
        ports = svc.body.get("ports")
        self.assertIsInstance(ports, list)
        self.assertEqual(len(ports), 1)

    def test_environment_env_pairs(self):
        tree = parse_compose(COMPOSE_BASIC)
        svc = tree.services[0]
        env = svc.body.get("environment")
        self.assertIsInstance(env, list)
        self.assertEqual(len(env), 2)


class CommentHandlingTests(unittest.TestCase):
    def test_inline_comment_stripped(self):
        text = (
            "services:\n"
            "  web:\n"
            "    image: nginx # pin me later\n"
        )
        tree = parse_compose(text)
        img = tree.services[0].scalar("image")
        self.assertEqual(img.value, "nginx")

    def test_hash_inside_quotes_preserved(self):
        text = (
            "services:\n"
            "  web:\n"
            "    image: \"nginx # ok\"\n"
        )
        tree = parse_compose(text)
        img = tree.services[0].scalar("image")
        # The dequote strips the surrounding quotes but preserves the #.
        self.assertIn("#", img.value)


class EmptyFileTests(unittest.TestCase):
    def test_blank(self):
        tree = parse_compose("")
        self.assertEqual(tree.services, [])


if __name__ == "__main__":
    unittest.main()
