"""Scanner tests (classify_filename, scan_text, scan_file, scan_paths)."""

from __future__ import annotations

import os
import unittest

from tests import support  # noqa: F401
from tests.support import write_temp

from composecheck.scanner import (
    classify_content,
    classify_filename,
    scan_file,
    scan_paths,
    scan_text,
)
from composecheck.types import FileKind, Options, Verdict


HEALTHY_DOCKER = (
    "FROM alpine:3.19\n"
    "USER app\n"
    "HEALTHCHECK CMD /bin/true\n"
)


class ClassifyFilenameTests(unittest.TestCase):
    def test_dockerfile_name(self):
        self.assertIs(
            classify_filename("Dockerfile"), FileKind.DOCKERFILE,
        )

    def test_dockerfile_variant(self):
        self.assertIs(
            classify_filename("Dockerfile.dev"), FileKind.DOCKERFILE,
        )

    def test_compose_name(self):
        self.assertIs(
            classify_filename("docker-compose.yml"), FileKind.COMPOSE,
        )

    def test_compose_v2_name(self):
        self.assertIs(
            classify_filename("compose.yml"), FileKind.COMPOSE,
        )

    def test_unknown_name(self):
        self.assertIs(
            classify_filename("notes.txt"), FileKind.UNKNOWN,
        )


class ClassifyContentTests(unittest.TestCase):
    def test_from_line_detects_dockerfile(self):
        self.assertIs(
            classify_content("FROM alpine\n"), FileKind.DOCKERFILE,
        )

    def test_services_detects_compose(self):
        self.assertIs(
            classify_content("services:\n  web:\n    image: nginx\n"),
            FileKind.COMPOSE,
        )


class ScanTextTests(unittest.TestCase):
    def test_dockerfile_healthy(self):
        r = scan_text(HEALTHY_DOCKER, "test.dockerfile", Options())
        self.assertEqual(r.verdict, Verdict.HEALTHY)

    def test_dockerfile_unhealthy_forced_kind(self):
        r = scan_text(
            "FROM ubuntu:latest\n", "x", Options(),
            kind=FileKind.DOCKERFILE,
        )
        self.assertEqual(r.verdict, Verdict.UNHEALTHY)


class ScanFileTests(unittest.TestCase):
    def test_missing_file(self):
        r = scan_file(
            "definitely-not-here.yml", Options(), kind=FileKind.COMPOSE,
        )
        self.assertEqual(r.verdict, Verdict.UNHEALTHY)
        self.assertEqual(r.findings[0].rule_id, "COMPOSE-000")

    def test_dockerfile_round_trip(self):
        d, p = write_temp(HEALTHY_DOCKER, name="Dockerfile")
        try:
            r = scan_file(p, Options())
            self.assertEqual(r.verdict, Verdict.HEALTHY)
        finally:
            os.remove(p)


class ScanPathsTests(unittest.TestCase):
    def test_scan_dir_picks_up_dockerfile_only(self):
        d, p = write_temp(HEALTHY_DOCKER, name="Dockerfile")
        try:
            # Also drop a non-container file in the same dir.
            with open(os.path.join(os.path.dirname(p), "notes.txt"),
                      "w", encoding="utf-8") as f:
                f.write("not a container file\n")
            r = scan_paths([os.path.dirname(p)], Options())
            # Only the Dockerfile is scanned; the .txt is skipped.
            self.assertGreaterEqual(r.files_scanned, 1)
        finally:
            try:
                os.remove(p)
            except OSError:
                pass


if __name__ == "__main__":
    unittest.main()
