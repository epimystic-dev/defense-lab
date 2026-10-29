"""Dockerfile parser.

The Dockerfile grammar is line-oriented: each non-blank non-comment
line is an instruction consisting of a case-insensitive keyword plus
arguments. A trailing ``\\`` at end of line joins the next line into
the current instruction (continuation).

Parser outputs ``Instruction`` records in file order. A later rule-
runner reads the list and emits findings. The parser is deliberately
permissive about whitespace and keyword case; the shape-rule layer is
where the strict interpretation lives.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List


# The Dockerfile keywords composecheck's rules address. Keywords unknown
# to this set are still captured (so a rule can see them) but their
# canonical case defaults to upper-case.
_KEYWORDS = {
    "FROM", "RUN", "CMD", "LABEL", "MAINTAINER", "EXPOSE", "ENV",
    "ADD", "COPY", "ENTRYPOINT", "VOLUME", "USER", "WORKDIR",
    "ARG", "ONBUILD", "STOPSIGNAL", "HEALTHCHECK", "SHELL",
}


@dataclass(frozen=True)
class Instruction:
    """One Dockerfile instruction, possibly spanning several physical
    lines via ``\\`` continuations.
    """

    keyword: str          # upper-cased keyword (e.g. "RUN")
    args: str             # arguments as a single space-joined string
    line: int             # 1-based line number of the first physical line
    raw_lines: List[str] = field(default_factory=list)


def parse_dockerfile(content: str) -> List[Instruction]:
    """Parse the full text of a Dockerfile into Instructions."""
    out: List[Instruction] = []
    lines = content.splitlines()
    i = 0
    # Dockerfile allows an escape-char directive at the very top to change
    # the continuation character, but it is rare and we honour only the
    # default. If present, the directive is just a comment to us.
    while i < len(lines):
        physical = lines[i]
        stripped = physical.strip()
        if not stripped or stripped.startswith("#"):
            i += 1
            continue
        # Collect continuation lines.
        start = i
        parts = [physical]
        text = physical.rstrip()
        while text.endswith("\\") and i + 1 < len(lines):
            # Drop the trailing backslash and append the next line.
            text = text[:-1]
            i += 1
            parts.append(lines[i])
            text = text + " " + lines[i].rstrip()
        # Tokenise the joined logical line.
        logical = text.strip()
        if not logical:
            i += 1
            continue
        toks = logical.split(None, 1)
        if not toks:
            i += 1
            continue
        kw_raw = toks[0]
        kw = kw_raw.upper()
        if kw not in _KEYWORDS:
            # A keyword we do not recognise - still capture so a rule
            # can inspect it. Set keyword to upper-case for stability.
            pass
        args = toks[1].strip() if len(toks) == 2 else ""
        out.append(Instruction(
            keyword=kw,
            args=args,
            line=start + 1,
            raw_lines=list(parts),
        ))
        i += 1
    return out


def by_keyword(instructions: List[Instruction], keyword: str) -> List[Instruction]:
    """Return every instruction with the given upper-case keyword."""
    kw = keyword.upper()
    return [ins for ins in instructions if ins.keyword == kw]


__all__ = ["Instruction", "parse_dockerfile", "by_keyword"]
