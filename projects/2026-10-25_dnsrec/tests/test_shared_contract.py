"""Shared contract tests for dnsrec.

Two contracts are locked here:

1. Package-surface invariants - the public API this module exports
   (``__version__``, ``Severity``, ``Verdict``, ``Finding``,
   ``ScanResult``, ``ALL_RULES``, ``Rule``, and a callable ``main``),
   plus the SPF-/DMARC-/DKIM- rule-ID convention.

2. CI-consumer invariants from defense-lab/docs/CONVENTIONS.md locked
   against the ``python -m <tool>`` subprocess entry:

     a. ``python -m dnsrec --version`` returns rc 0.
     b. ``python -m dnsrec --help`` returns rc 0.
     c. ``python -m dnsrec <healthy_zone>`` returns rc 0.
     d. ``python -m dnsrec <weak_zone>`` returns non-zero with the
        SPF-001 anchor on stdout.
     e. An unknown flag returns rc 2.

   The clean / dirty inputs are the shipped demonstration fixtures.
"""

from __future__ import annotations

import os
import subprocess
import sys
import unittest

from tests import support  # noqa: F401

import dnsrec
from dnsrec.cli import main
from dnsrec.rules import REGISTRY


PKG_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXAMPLES_DIR = os.path.join(PKG_DIR, "examples")


_VALID_PREFIXES = ("SPF-", "DMARC-", "DKIM-")


def _run(*args: str) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env["PYTHONPATH"] = PKG_DIR + os.pathsep + env.get("PYTHONPATH", "")
    return subprocess.run(
        [sys.executable, "-m", "dnsrec", *args],
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
    )


class PackageSurfaceTests(unittest.TestCase):
    def test_version_str(self):
        self.assertIsInstance(dnsrec.__version__, str)
        self.assertRegex(dnsrec.__version__, r"^\d+\.\d+\.\d+$")

    def test_all_exports_present(self):
        for name in ("Severity", "Verdict", "Finding", "ScanResult",
                     "ALL_RULES", "Rule"):
            self.assertTrue(hasattr(dnsrec, name), name)

    def test_shared_rule_table_alias_is_internal_registry(self):
        self.assertIs(dnsrec.ALL_RULES, REGISTRY)

    def test_cli_main_callable(self):
        self.assertTrue(callable(main))

    def test_rule_ids_use_expected_prefix(self):
        self.assertTrue(REGISTRY, "rule registry is empty")
        for r in REGISTRY:
            self.assertTrue(
                any(r.id.startswith(p) for p in _VALID_PREFIXES),
                r.id,
            )

    def test_every_rule_cites_a_public_control(self):
        for r in REGISTRY:
            self.assertTrue(r.citation.strip(), r.id)


class SharedContractInvariants(unittest.TestCase):
    def test_version_returns_zero(self):
        r = _run("--version")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(
            r.stdout.strip(), "dnsrec " + dnsrec.__version__)

    def test_help_returns_zero(self):
        # argparse prints the help to stdout and exits 0, but it also
        # requires at least one positional for the main run; --help
        # itself bypasses the positional requirement.
        r = _run("--help")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("dnsrec", r.stdout)

    def test_unknown_flag_returns_two(self):
        r = _run("--definitely-not-a-flag", "/dev/null")
        self.assertEqual(r.returncode, 2)

    def test_known_clean_input_returns_zero(self):
        path = os.path.join(EXAMPLES_DIR, "healthy_zone.txt")
        self.assertTrue(os.path.isfile(path))
        r = _run(path)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_known_dirty_input_returns_nonzero(self):
        path = os.path.join(EXAMPLES_DIR, "weak_zone.txt")
        self.assertTrue(os.path.isfile(path))
        r = _run(path)
        self.assertNotEqual(
            r.returncode, 0,
            "dnsrec exited 0 on a known-dirty input",
        )
        self.assertIn(
            "SPF-001", r.stdout,
            "expected SPF-001 anchor on weak fixture; stdout: "
            + repr(r.stdout),
        )


if __name__ == "__main__":
    unittest.main()
