"""Shared test helpers for headerscheck."""

from __future__ import annotations

import io
import os
import tempfile
from typing import Iterable, Optional, Sequence, Tuple

from headerscheck.cli import main as cli_main
from headerscheck.parse import load
from headerscheck.rules import run_all
from headerscheck.types import Finding, Options


FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")

_PROJECT_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..")
)
_LOCAL_TMP = os.path.join(_PROJECT_ROOT, ".pytest_tmp")
os.makedirs(_LOCAL_TMP, exist_ok=True)
tempfile.tempdir = _LOCAL_TMP


def scan_string(
    content: str,
    options: Optional[Options] = None,
    path: str = "in-memory",
) -> Sequence[Finding]:
    options = options or Options()
    responses, err = load(content)
    if err is not None:
        return []
    out = []
    for r in responses:
        out.extend(run_all(r, path, options))
    return out


def write_temp(content: str, name: str = "response.http") -> Tuple[str, str]:
    d = tempfile.mkdtemp(prefix="headerscheck_")
    p = os.path.join(d, name)
    with open(p, "w", encoding="utf-8") as f:
        f.write(content)
    return d, p


def run_cli(argv: Sequence[str]) -> Tuple[int, str, str]:
    out = io.StringIO()
    err = io.StringIO()
    rc = cli_main(list(argv), stdout=out, stderr=err)
    return rc, out.getvalue(), err.getvalue()


def rule_ids(findings: Iterable[Finding]) -> Tuple[str, ...]:
    return tuple(f.rule_id for f in findings)


def fixture_path(name: str) -> str:
    return os.path.join(FIXTURES, name)
