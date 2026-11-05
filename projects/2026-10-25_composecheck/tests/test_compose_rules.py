"""Compose rule tests (DC-001..DC-010)."""

from __future__ import annotations

import unittest

from tests import support  # noqa: F401
from tests.support import rule_ids, scan_compose_string


def _ids(text, options=None):
    return rule_ids(scan_compose_string(text, options))


# A minimal service with cap_drop: ALL + user set so the catch-all rules
# (DC-005, DC-008, DC-009) do not fire; individual tests then layer the
# defect under test on top.
HEALTHY_BASE = """\
version: "3.8"
services:
  app:
    image: nginx:1.25
    user: "1001:1001"
    read_only: true
    mem_limit: 128m
    cpus: 0.5
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE
    security_opt:
      - no-new-privileges:true
"""


class DC001PrivilegedTests(unittest.TestCase):
    def test_privileged_true_fires(self):
        text = HEALTHY_BASE + "    privileged: true\n"
        self.assertIn("DC-001", _ids(text))

    def test_privileged_false_clean(self):
        text = HEALTHY_BASE + "    privileged: false\n"
        self.assertNotIn("DC-001", _ids(text))

    def test_privileged_absent_clean(self):
        self.assertNotIn("DC-001", _ids(HEALTHY_BASE))


class DC002NetworkModeTests(unittest.TestCase):
    def test_host_fires(self):
        text = HEALTHY_BASE + "    network_mode: host\n"
        self.assertIn("DC-002", _ids(text))

    def test_bridge_clean(self):
        text = HEALTHY_BASE + "    network_mode: bridge\n"
        self.assertNotIn("DC-002", _ids(text))


class DC003PidIpcTests(unittest.TestCase):
    def test_pid_host_fires(self):
        text = HEALTHY_BASE + "    pid: host\n"
        self.assertIn("DC-003", _ids(text))

    def test_ipc_host_fires(self):
        text = HEALTHY_BASE + "    ipc: host\n"
        self.assertIn("DC-003", _ids(text))


class DC004CapAddTests(unittest.TestCase):
    def test_sys_admin_fires(self):
        text = """\
version: "3.8"
services:
  app:
    image: nginx:1.25
    user: "1001:1001"
    cpus: 0.5
    cap_drop:
      - ALL
    cap_add:
      - SYS_ADMIN
"""
        self.assertIn("DC-004", _ids(text))

    def test_net_bind_service_clean(self):
        self.assertNotIn("DC-004", _ids(HEALTHY_BASE))

    def test_cap_prefix_normalised(self):
        text = """\
version: "3.8"
services:
  app:
    image: nginx:1.25
    user: "1001:1001"
    cpus: 0.5
    cap_drop:
      - ALL
    cap_add:
      - CAP_SYS_ADMIN
"""
        self.assertIn("DC-004", _ids(text))


class DC005CapDropTests(unittest.TestCase):
    def test_missing_cap_drop_fires(self):
        text = """\
version: "3.8"
services:
  app:
    image: nginx:1.25
    user: "1001:1001"
    cpus: 0.5
"""
        self.assertIn("DC-005", _ids(text))


class DC006DockerSocketTests(unittest.TestCase):
    def test_docker_socket_mount_fires(self):
        text = HEALTHY_BASE + """\
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
"""
        self.assertIn("DC-006", _ids(text))


class DC007EnvSecretTests(unittest.TestCase):
    def test_env_password_fires(self):
        text = HEALTHY_BASE + """\
    environment:
      - DATABASE_PASSWORD=changeme
      - PORT=8080
"""
        self.assertIn("DC-007", _ids(text))

    def test_env_api_token_fires(self):
        text = HEALTHY_BASE + """\
    environment:
      - API_TOKEN=notasecret
"""
        self.assertIn("DC-007", _ids(text))

    def test_env_var_reference_clean(self):
        text = HEALTHY_BASE + """\
    environment:
      - API_TOKEN=${API_TOKEN}
"""
        self.assertNotIn("DC-007", _ids(text))


class DC008UserTests(unittest.TestCase):
    def test_no_user_fires(self):
        text = """\
version: "3.8"
services:
  app:
    image: nginx:1.25
    cpus: 0.5
    cap_drop:
      - ALL
"""
        self.assertIn("DC-008", _ids(text))

    def test_root_user_fires(self):
        text = """\
version: "3.8"
services:
  app:
    image: nginx:1.25
    user: root
    cpus: 0.5
    cap_drop:
      - ALL
"""
        self.assertIn("DC-008", _ids(text))

    def test_uid_zero_with_nonroot_group_fires(self):
        # user: "0:1000" runs as uid 0 regardless of the gid; the group
        # portion does not affect root-ness. Previously this passed
        # silently because the check only matched the exact strings
        # "0", "root", and "0:0".
        text = """\
version: "3.8"
services:
  app:
    image: nginx:1.25
    user: "0:1000"
    cpus: 0.5
    cap_drop:
      - ALL
"""
        self.assertIn("DC-008", _ids(text))

    def test_root_with_nonroot_group_fires(self):
        # user: "root:nogroup" is a plausible-looking "hardened" value;
        # the operator thinks naming a non-root group drops privilege,
        # but Docker uses the user portion to pick the uid and nogroup
        # does not change the fact that this runs as uid 0.
        text = """\
version: "3.8"
services:
  app:
    image: nginx:1.25
    user: "root:nogroup"
    cpus: 0.5
    cap_drop:
      - ALL
"""
        self.assertIn("DC-008", _ids(text))

    def test_root_with_root_group_fires(self):
        # Parity with the pre-fix "0:0" case for the symbolic spelling.
        text = """\
version: "3.8"
services:
  app:
    image: nginx:1.25
    user: "root:root"
    cpus: 0.5
    cap_drop:
      - ALL
"""
        self.assertIn("DC-008", _ids(text))

    def test_uid_zero_with_group_unquoted_fires(self):
        # YAML parses 0:1000 as a scalar; the uid portion is still 0.
        text = """\
version: "3.8"
services:
  app:
    image: nginx:1.25
    user: 0:1000
    cpus: 0.5
    cap_drop:
      - ALL
"""
        self.assertIn("DC-008", _ids(text))

    def test_nonroot_uid_with_gid_zero_clean(self):
        # Disjointness pin: uid 1000 with gid 0 is not uid 0 and must
        # not fire DC-008. gid-0 group membership is a different and
        # narrower concern (file-group access) that this rule does not
        # own.
        text = """\
version: "3.8"
services:
  app:
    image: nginx:1.25
    user: "1000:0"
    cpus: 0.5
    cap_drop:
      - ALL
"""
        self.assertNotIn("DC-008", _ids(text))

    def test_nonroot_user_baseline_clean(self):
        # Baseline pin: a well-formed non-root user:group stays clean.
        text = """\
version: "3.8"
services:
  app:
    image: nginx:1.25
    user: "1001:1001"
    cpus: 0.5
    cap_drop:
      - ALL
"""
        self.assertNotIn("DC-008", _ids(text))


class DC009ResourceLimitsTests(unittest.TestCase):
    def test_no_limits_fires(self):
        text = """\
version: "3.8"
services:
  app:
    image: nginx:1.25
    user: "1001:1001"
    cap_drop:
      - ALL
"""
        self.assertIn("DC-009", _ids(text))

    def test_mem_limit_clean(self):
        text = """\
version: "3.8"
services:
  app:
    image: nginx:1.25
    user: "1001:1001"
    mem_limit: 128m
    cap_drop:
      - ALL
"""
        self.assertNotIn("DC-009", _ids(text))

    def test_deploy_limits_clean(self):
        text = """\
version: "3.8"
services:
  app:
    image: nginx:1.25
    user: "1001:1001"
    cap_drop:
      - ALL
    deploy:
      resources:
        limits:
          cpus: "0.5"
          memory: 128M
"""
        self.assertNotIn("DC-009", _ids(text))


class DC010SecurityOptTests(unittest.TestCase):
    def test_seccomp_unconfined_fires(self):
        text = HEALTHY_BASE + """\
    volumes: []
    _extra_security_opt_marker: unused
"""
        # Replace the clean security_opt in HEALTHY_BASE with an unsafe one.
        text = text.replace(
            "- no-new-privileges:true",
            "- seccomp:unconfined",
        )
        self.assertIn("DC-010", _ids(text))

    def test_apparmor_unconfined_fires(self):
        text = HEALTHY_BASE.replace(
            "- no-new-privileges:true",
            "- apparmor:unconfined",
        )
        self.assertIn("DC-010", _ids(text))


if __name__ == "__main__":
    unittest.main()
