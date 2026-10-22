"""Command-line entry for headerscheck."""

from __future__ import annotations

import argparse
import sys
from typing import Optional, Sequence, TextIO

from . import __version__
from .report import write_json, write_text
from .scanner import scan_paths
from .types import Options
from .verdict import exit_code


def _parse_argv(argv: Sequence[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="headerscheck",
        description=(
            "Static security-header posture linter for saved HTTP"
            " responses. Reads a raw HTTP response, a headers-only"
            " file, or a HAR entry the operator has captured and"
            " reports posture defects against OWASP Secure Headers,"
            " OWASP ASVS v4, IETF RFC 6265bis, and RFC 6797."
            " Does not touch any live service."
        ),
    )
    p.add_argument(
        "--version", action="version",
        version="headerscheck " + __version__,
    )
    p.add_argument(
        "paths", nargs="+",
        help="response file(s) or director(y|ies) to scan",
    )
    p.add_argument(
        "--json", action="store_true",
        help="emit machine-readable JSON instead of text",
    )
    p.add_argument(
        "--strict", action="store_true",
        help=(
            "surface INFO rules and treat INFO-only outcomes as"
            " needs-attention"
        ),
    )
    p.add_argument(
        "--include-info", action="store_true",
        help="surface INFO rules without upgrading verdict",
    )
    p.add_argument(
        "--disable", action="append", default=[],
        metavar="RULE_ID",
        help="disable a rule (repeatable)",
    )
    p.add_argument(
        "--only", action="append", default=[],
        metavar="RULE_ID",
        help="run only the given rule (repeatable)",
    )
    g = p.add_mutually_exclusive_group()
    g.add_argument(
        "--assume-https", dest="assume_https", action="store_true",
        default=None,
        help="treat captures as HTTPS (default: inferred from URL)",
    )
    g.add_argument(
        "--assume-http", dest="assume_http", action="store_true",
        help="treat captures as plain HTTP",
    )
    return p.parse_args(list(argv))


def main(
    argv: Optional[Sequence[str]] = None,
    stdout: Optional[TextIO] = None,
    stderr: Optional[TextIO] = None,
) -> int:
    stdout = stdout if stdout is not None else sys.stdout
    stderr = stderr if stderr is not None else sys.stderr
    args = _parse_argv(argv if argv is not None else sys.argv[1:])
    assume: Optional[bool] = None
    if args.assume_https:
        assume = True
    elif args.assume_http:
        assume = False
    options = Options(
        strict=args.strict,
        include_info=args.include_info,
        disabled=tuple(args.disable),
        only=tuple(args.only),
        assume_https=assume,
    )
    result = scan_paths(args.paths, options)
    if args.json:
        write_json(result, stdout)
    else:
        write_text(result, stdout)
    return exit_code(result.verdict, options)


__all__ = ["main"]
