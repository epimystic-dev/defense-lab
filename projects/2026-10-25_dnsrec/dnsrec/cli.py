"""Command-line entry for dnsrec.

Invokable as ``python -m dnsrec`` (via __main__.py). argparse owns
``--help`` and unknown-flag handling, which keeps the exit-code
contract documented in defense-lab/docs/CONVENTIONS.md intact.
"""

from __future__ import annotations

import argparse
import sys
from typing import Optional, Sequence, TextIO

from . import __version__
from .report import write_json, write_text
from .scanner import scan_paths
from .types import Options, RecordKind
from .verdict import exit_code


def _parse_argv(argv: Sequence[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="dnsrec",
        description=(
            "Static posture linter for SPF, DMARC, and DKIM DNS records."
            " Reads a BIND-style zone file the operator has saved and"
            " reports posture defects against RFC 7208 (SPF), RFC 7489"
            " (DMARC), RFC 6376 (DKIM), RFC 8463 (DKIM Ed25519),"
            " NIST SP 800-177, and M3AAWG BCP. Does not query any DNS"
            " server."
        ),
    )
    p.add_argument(
        "--version", action="version", version="dnsrec " + __version__,
    )
    p.add_argument(
        "paths", nargs="+",
        help="zone file(s) or bare TXT record file(s) to scan",
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
        "--kind", choices=["spf", "dmarc", "dkim"],
        default=None,
        help=(
            "treat each non-blank line in each input as a bare record"
            " value of the given kind (useful for feeding"
            " dig +short TXT output)"
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
    force_kind: Optional[RecordKind] = None
    if args.kind == "spf":
        force_kind = RecordKind.SPF
    elif args.kind == "dmarc":
        force_kind = RecordKind.DMARC
    elif args.kind == "dkim":
        force_kind = RecordKind.DKIM
    options = Options(
        strict=args.strict,
        include_info=args.include_info,
        disabled=tuple(args.disable),
        only=tuple(args.only),
        force_kind=force_kind,
    )
    result = scan_paths(args.paths, options)
    if args.json:
        write_json(result, stdout)
    else:
        write_text(result, stdout)
    return exit_code(result.verdict, options)


__all__ = ["main"]
