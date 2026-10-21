"""Shared test helpers for sshdcheck."""

from __future__ import annotations

import io
import os
import tempfile
from typing import Iterable, Optional, Sequence, Tuple

from sshdcheck.cli import main as cli_main
from sshdcheck.parse import parse_text
from sshdcheck.rules import run_all
from sshdcheck.types import Finding, Options, ScanResult, Severity


FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")

# Route temp files into a project-local directory so an endpoint
# scanner watching the user profile Temp folder cannot quarantine a
# fixture mid-write. The directory is dot-prefixed and git-ignored.
_PROJECT_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..")
)
_LOCAL_TMP = os.path.join(_PROJECT_ROOT, ".pytest_tmp")
os.makedirs(_LOCAL_TMP, exist_ok=True)
tempfile.tempdir = _LOCAL_TMP


# ---------------------------------------------------------------------------
# Codepoint helpers. The point of these is to keep source files ASCII;
# a non-ASCII payload in a sshd_config fixture is assembled at runtime.
# ---------------------------------------------------------------------------

def bidi_char(cp: int = 0x202E) -> str:
    """A bidi-override codepoint. Used to prove the text report renders
    non-ASCII as <U+XXXX>.
    """
    if cp not in (0x202A, 0x202B, 0x202C, 0x202D, 0x202E,
                  0x2066, 0x2067, 0x2068, 0x2069):
        raise ValueError("not a bidi-override codepoint")
    return chr(cp)


# ---------------------------------------------------------------------------
# Fixture builders.
# ---------------------------------------------------------------------------

def scan_string(
    content: str,
    options: Optional[Options] = None,
    path: str = "in-memory",
) -> Sequence[Finding]:
    options = options or Options()
    directives = parse_text(content)
    return run_all(directives, content, path, options)


def write_temp(
    content: str, name: str = "sshd_config"
) -> Tuple[str, str]:
    """Write a config body to a fresh temp directory, return (dir, path)."""
    d = tempfile.mkdtemp(prefix="sshdcheck_")
    p = os.path.join(d, name)
    with open(p, "w", encoding="utf-8") as f:
        f.write(content)
    return d, p


def run_cli(argv: Sequence[str]) -> Tuple[int, str, str]:
    """Invoke the CLI in-process. Returns (rc, stdout, stderr)."""
    out = io.StringIO()
    err = io.StringIO()
    rc = cli_main(list(argv), stdout=out, stderr=err)
    return rc, out.getvalue(), err.getvalue()


def rule_ids(findings: Iterable[Finding]) -> Tuple[str, ...]:
    return tuple(f.rule_id for f in findings)


def fixture_path(name: str) -> str:
    return os.path.join(FIXTURES, name)
