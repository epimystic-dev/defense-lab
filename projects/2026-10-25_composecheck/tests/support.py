"""Shared test helpers for composecheck."""

from __future__ import annotations

import io
import os
import tempfile
from typing import Iterable, Optional, Sequence, Tuple

from composecheck.cli import main as cli_main
from composecheck.parse_compose import parse_compose
from composecheck.parse_dockerfile import parse_dockerfile
from composecheck.rules import run_all
from composecheck.types import Finding, Options


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


def scan_dockerfile_string(
    content: str,
    options: Optional[Options] = None,
    path: str = "in-memory",
) -> Sequence[Finding]:
    options = options or Options()
    instructions = parse_dockerfile(content)
    return run_all(instructions, None, path, options)


def scan_compose_string(
    content: str,
    options: Optional[Options] = None,
    path: str = "in-memory",
) -> Sequence[Finding]:
    options = options or Options()
    tree = parse_compose(content)
    return run_all([], tree, path, options)


def write_temp(
    content: str, name: str = "input",
) -> Tuple[str, str]:
    """Write content to a fresh temp directory, return (dir, path)."""
    d = tempfile.mkdtemp(prefix="composecheck_")
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
