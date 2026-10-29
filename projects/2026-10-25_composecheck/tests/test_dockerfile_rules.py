"""Dockerfile rule tests (DKF-001..DKF-010)."""

from __future__ import annotations

import unittest

from tests import support  # noqa: F401
from tests.support import rule_ids, scan_dockerfile_string

from composecheck.types import Options


def _ids(text, options=None):
    return rule_ids(scan_dockerfile_string(text, options))


class DKF001RootTests(unittest.TestCase):
    def test_no_user_fires(self):
        self.assertIn("DKF-001", _ids("FROM alpine:3.19\n"))

    def test_user_root_fires(self):
        self.assertIn("DKF-001", _ids("FROM alpine:3.19\nUSER root\n"))

    def test_user_zero_fires(self):
        self.assertIn("DKF-001", _ids("FROM alpine:3.19\nUSER 0\n"))

    def test_non_root_user_clean(self):
        self.assertNotIn("DKF-001", _ids("FROM alpine:3.19\nUSER app\n"))


class DKF002TagTests(unittest.TestCase):
    def test_latest_fires(self):
        self.assertIn("DKF-002", _ids("FROM alpine:latest\n"))

    def test_no_tag_fires(self):
        self.assertIn("DKF-002", _ids("FROM alpine\n"))

    def test_pinned_tag_clean(self):
        self.assertNotIn("DKF-002", _ids("FROM alpine:3.19\n"))

    def test_digest_pin_clean(self):
        text = "FROM alpine@sha256:" + ("a" * 64) + "\n"
        self.assertNotIn("DKF-002", _ids(text))

    def test_scratch_clean(self):
        self.assertNotIn("DKF-002", _ids("FROM scratch\n"))


class DKF003AddTests(unittest.TestCase):
    def test_add_local_file_fires(self):
        text = "FROM alpine:3.19\nUSER app\nADD ./config.txt /etc/x\n"
        self.assertIn("DKF-003", _ids(text))

    def test_add_tar_clean(self):
        text = "FROM alpine:3.19\nUSER app\nADD ./payload.tar /app\n"
        self.assertNotIn("DKF-003", _ids(text))

    def test_add_url_clean(self):
        text = "FROM alpine:3.19\nUSER app\nADD https://example.invalid/x.sh /x.sh\n"
        self.assertNotIn("DKF-003", _ids(text))


class DKF004AptHygieneTests(unittest.TestCase):
    def test_apt_install_without_hygiene_fires(self):
        text = (
            "FROM debian:12.4\nUSER app\n"
            "RUN apt-get update && apt-get install -y curl\n"
        )
        self.assertIn("DKF-004", _ids(text))

    def test_apt_install_with_hygiene_clean(self):
        text = (
            "FROM debian:12.4\nUSER app\n"
            "RUN apt-get update && apt-get install -y --no-install-recommends curl \\\n"
            " && rm -rf /var/lib/apt/lists/*\n"
        )
        self.assertNotIn("DKF-004", _ids(text))


class DKF005EnvSecretTests(unittest.TestCase):
    def test_env_password_fires(self):
        text = (
            "FROM alpine:3.19\nUSER app\n"
            "ENV DATABASE_PASSWORD=changeme\n"
        )
        self.assertIn("DKF-005", _ids(text))

    def test_env_api_key_fires(self):
        text = (
            "FROM alpine:3.19\nUSER app\n"
            "ENV API_KEY=notasecret\n"
        )
        self.assertIn("DKF-005", _ids(text))

    def test_env_log_level_clean(self):
        text = (
            "FROM alpine:3.19\nUSER app\n"
            "ENV LOG_LEVEL=info\n"
        )
        self.assertNotIn("DKF-005", _ids(text))


class DKF006PipeToShellTests(unittest.TestCase):
    def test_curl_bash_fires(self):
        text = (
            "FROM alpine:3.19\nUSER app\n"
            "RUN curl https://example.invalid/i.sh | bash\n"
        )
        self.assertIn("DKF-006", _ids(text))

    def test_wget_sh_fires(self):
        text = (
            "FROM alpine:3.19\nUSER app\n"
            "RUN wget -O - https://example.invalid/i.sh | sh\n"
        )
        self.assertIn("DKF-006", _ids(text))

    def test_normal_curl_clean(self):
        text = (
            "FROM alpine:3.19\nUSER app\n"
            "RUN curl -o /tmp/i.sh https://example.invalid/i.sh\n"
        )
        self.assertNotIn("DKF-006", _ids(text))


class DKF007SudoTests(unittest.TestCase):
    def test_sudo_fires(self):
        text = (
            "FROM alpine:3.19\nUSER app\n"
            "RUN sudo mkdir /x\n"
        )
        self.assertIn("DKF-007", _ids(text))

    def test_no_sudo_clean(self):
        text = (
            "FROM alpine:3.19\nUSER app\n"
            "RUN mkdir /x\n"
        )
        self.assertNotIn("DKF-007", _ids(text))


class DKF008HealthcheckTests(unittest.TestCase):
    def test_missing_healthcheck_fires_with_strict(self):
        text = "FROM alpine:3.19\nUSER app\n"
        self.assertIn("DKF-008", _ids(text, Options(strict=True)))

    def test_healthcheck_present_clean(self):
        text = (
            "FROM alpine:3.19\nUSER app\n"
            "HEALTHCHECK CMD /bin/true\n"
        )
        self.assertNotIn("DKF-008", _ids(text, Options(strict=True)))


class DKF009Chmod777Tests(unittest.TestCase):
    def test_chmod_777_fires(self):
        text = (
            "FROM alpine:3.19\nUSER app\n"
            "RUN chmod 777 /opt\n"
        )
        self.assertIn("DKF-009", _ids(text))

    def test_chmod_recursive_777_fires(self):
        text = (
            "FROM alpine:3.19\nUSER app\n"
            "RUN chmod -R 777 /opt\n"
        )
        self.assertIn("DKF-009", _ids(text))

    def test_a_rwx_fires(self):
        text = (
            "FROM alpine:3.19\nUSER app\n"
            "RUN chmod a=rwx /opt\n"
        )
        self.assertIn("DKF-009", _ids(text))

    def test_safe_chmod_clean(self):
        text = (
            "FROM alpine:3.19\nUSER app\n"
            "RUN chmod 644 /opt/config\n"
        )
        self.assertNotIn("DKF-009", _ids(text))


class DKF010ChownRootTests(unittest.TestCase):
    def test_chown_root_fires(self):
        text = (
            "FROM alpine:3.19\nUSER app\n"
            "COPY --chown=root:root ./app /app\n"
        )
        self.assertIn("DKF-010", _ids(text))

    def test_chown_zero_fires(self):
        text = (
            "FROM alpine:3.19\nUSER app\n"
            "COPY --chown=0:0 ./app /app\n"
        )
        self.assertIn("DKF-010", _ids(text))

    def test_chown_app_clean(self):
        text = (
            "FROM alpine:3.19\nUSER app\n"
            "COPY --chown=app:app ./app /app\n"
        )
        self.assertNotIn("DKF-010", _ids(text))


if __name__ == "__main__":
    unittest.main()
