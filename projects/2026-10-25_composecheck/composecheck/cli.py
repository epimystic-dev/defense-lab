"""Command-line entry for composecheck.

Invokable as ``python -m composecheck`` (via __main__.py).
"""

from __future__ import annotations

import argparse
import sys
from typing import Optional, Sequence, TextIO

from . import __version__
from .report import write_json, write_text
from .scanner import scan_paths
from .types import FileKind, Options
from .verdict import exit_code


def _parse_argv(argv: Sequence[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="composecheck",
        description=(
            "Static hardening linter for Dockerfile and docker-compose"
            " files. Reads a saved Dockerfile and / or"
            " docker-compose.yml and reports posture defects against"
            " the CIS Docker Benchmark, NIST SP 800-190, and OWASP"
            " Docker Top 10. Does not pull images, build containers,"
            " or connect to a Docker daemon."
        ),
    )
    p.add_argument(
        "--version", action="version",
        version="composecheck " + __version__,
    )
    p.add_argument(
        "paths", nargs="+",
        help="Dockerfile / docker-compose file(s) or director(y|ies) to scan",
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
        help="surface INFO rules in output (without upgrading verdict)",
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
    p.add_argument(
        "--as", choices=["dockerfile", "compose"],
        default=None, dest="as_kind",
        help=(
            "force every input to be treated as the named file kind"
            " (useful when the filename does not match a canonical"
            " pattern)"
        ),
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
    forced: Optional[FileKind] = None
    if args.as_kind == "dockerfile":
        forced = FileKind.DOCKERFILE
    elif args.as_kind == "compose":
        forced = FileKind.COMPOSE
    options = Options(
        strict=args.strict,
        include_info=args.include_info,
        disabled=tuple(args.disable),
        only=tuple(args.only),
    )
    result = scan_paths(args.paths, options, kind=forced)
    if args.json:
        write_json(result, stdout)
    else:
        write_text(result, stdout)
    return exit_code(result.verdict, options)


__all__ = ["main"]
