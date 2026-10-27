"""Zone-file and bare-record parser for dnsrec.

Two input shapes are accepted:

  1. BIND-style zone-file snippet (the default). Lines look like

         example.com.         IN TXT "v=spf1 -all"
         _dmarc.example.com.  3600 IN TXT "v=DMARC1; p=reject"
         sel._domainkey       IN TXT ( "v=DKIM1; k=rsa; "
                                       "p=MIGf..." )

     Comments (``;`` to end of line), blank lines, and ``$ORIGIN`` /
     ``$TTL`` control statements are honoured per RFC 1035 lexical
     rules. Multi-line records joined with ``( )`` are collapsed.

  2. Bare TXT record value, one per line, when the CLI is run with
     ``--kind {spf, dmarc, dkim}``. The parser then treats each
     non-blank non-comment line as the TXT body of a record of the
     declared kind, with the owner synthesised from the kind (``@`` for
     SPF, ``_dmarc`` for DMARC, ``selector._domainkey`` for DKIM).

Classification by kind is a shape call:

  * SPF: owner is a plain domain name, value starts with ``v=spf1``.
  * DMARC: owner begins ``_dmarc.`` (or is literally ``_dmarc``),
    value starts with ``v=DMARC1``.
  * DKIM: owner contains ``._domainkey`` or starts with
    ``selector`` where ``selector._domainkey.`` precedes the apex,
    value starts with ``v=DKIM1`` or declares ``k=`` or ``p=``.

The parser is deliberately permissive about owner-name case and
whitespace, because real-world zone files vary. Case is folded to
lowercase in the returned ``Record.owner``.
"""

from __future__ import annotations

import re
from typing import List, Optional

from .types import Record, RecordKind


_DMARC_OWNER_RE = re.compile(r"(^|\.)_dmarc(\.|$)", re.IGNORECASE)
_DKIM_OWNER_RE = re.compile(r"(^|\.)_domainkey(\.|$)", re.IGNORECASE)


def _strip_comment(line: str) -> str:
    """Remove a ``;`` comment, honouring that ``;`` inside a quoted
    string is literal (BIND zone-file syntax).
    """
    out = []
    in_q = False
    for ch in line:
        if ch == '"':
            in_q = not in_q
            out.append(ch)
            continue
        if ch == ';' and not in_q:
            break
        out.append(ch)
    return "".join(out)


def _canonical_owner(owner: str, origin: Optional[str]) -> str:
    """Lower-case the owner; append the current $ORIGIN when it is
    unqualified; strip a trailing dot. Returns the empty string for an
    owner we cannot interpret.
    """
    o = owner.strip()
    if not o:
        return ""
    if o == "@":
        return (origin or "").lower().rstrip(".")
    if o.endswith("."):
        return o.lower().rstrip(".")
    if origin:
        base = origin.rstrip(".")
        return (o + "." + base).lower()
    return o.lower()


def _concat_quoted_strings(value: str) -> str:
    """Join an RFC 1035-style sequence of adjacent ``"..."`` strings
    into one logical string. Strings are concatenated verbatim (per
    RFC 1035 and RFC 7208 section 3.3). Unquoted whitespace between
    them is ignored. Backslash escapes inside a quoted string are
    passed through literally; backslash-dot escapes are rare in TXT
    data and are preserved for the caller to interpret.
    """
    parts: List[str] = []
    cur: List[str] = []
    in_q = False
    esc = False
    for ch in value:
        if esc:
            cur.append(ch)
            esc = False
            continue
        if ch == '\\' and in_q:
            esc = True
            continue
        if ch == '"':
            if in_q:
                parts.append("".join(cur))
                cur = []
                in_q = False
            else:
                in_q = True
            continue
        if in_q:
            cur.append(ch)
    if in_q:
        # Unterminated quote: salvage what we have.
        parts.append("".join(cur))
    return "".join(parts)


def _classify(owner: str, body: str) -> RecordKind:
    """Classify a parsed TXT record body.

    The version-tag match is intentionally loose (``v=dmarc``, ``v=dkim``,
    ``v=spf`` rather than ``v=dmarc1`` / ``v=dkim1`` / ``v=spf1``) so a
    near-miss on the version string lands in the right kind-bucket and
    is caught by the version rule (DMARC-004, DKIM-001, SPF-008) rather
    than silently classified as OTHER and dropped.
    """
    b = body.strip()
    bl = b.lower()
    o = owner.lower()
    if _DMARC_OWNER_RE.search(o) or bl.startswith("v=dmarc"):
        return RecordKind.DMARC
    if _DKIM_OWNER_RE.search(o) or bl.startswith("v=dkim"):
        return RecordKind.DKIM
    if bl.startswith("v=spf"):
        return RecordKind.SPF
    return RecordKind.OTHER


def _is_control(token: str) -> bool:
    return token.startswith("$")


def _join_multiline(lines: List[str], start: int) -> (int, str):
    """BIND multi-line record: once a ``(`` is seen inside the record
    body, lines concatenate until the matching ``)``. Returns the index
    of the last consumed line and the joined body.
    """
    buf: List[str] = []
    depth = 0
    i = start
    while i < len(lines):
        text = _strip_comment(lines[i])
        for ch in text:
            if ch == '(':
                depth += 1
            elif ch == ')':
                depth -= 1
        buf.append(text)
        i += 1
        if depth <= 0:
            break
    return (i - 1, " ".join(buf).replace("(", " ").replace(")", " "))


_TXT_SPLIT_RE = re.compile(r"\s+", re.ASCII)


def _parse_zone_line_block(block: str) -> Optional[tuple]:
    """Parse one logical record line (already joined for multi-line
    continuations). Returns (owner, body) when the line is a TXT
    record, else None.

    A zone record line is::

        <owner> [<ttl>] [<class>] TXT <rdata>

    where <ttl> is a number, <class> is IN/CH/HS, and <rdata> is one
    or more quoted strings.
    """
    text = block.strip()
    if not text:
        return None
    # The parser handles only TXT lines; others are ignored.
    low = text.lower()
    # Look for ' txt ' or 'txt(' or 'txt"'
    m = re.search(r"\btxt\b", low)
    if not m:
        return None
    before = text[:m.start()].strip()
    after = text[m.end():].strip()
    # ``before`` is "<owner> [<ttl>] [<class>]" with optional
    # elements. Owner may be ``@``. If before is empty, the owner
    # inherits from the previous record (BIND rule), but dnsrec requires
    # explicit owners for clarity; we return None in that case to force
    # the caller to supply the owner.
    tokens = before.split()
    if not tokens:
        return None
    owner_tok = tokens[0]
    # Reject lines whose "TXT" is not actually the type (e.g. "TXT" as
    # part of a longer word). Simple test: the thing before TXT is
    # expected to end with a class (IN/CH/HS) or a TTL or nothing more
    # than the owner.
    body = _concat_quoted_strings(after)
    if not body:
        # No quoted strings; this is probably not a TXT record even
        # though 'txt' appears.
        return None
    return (owner_tok, body)


def parse_zone_text(content: str) -> List[Record]:
    """Parse a BIND-style zone-file snippet into Records.

    Only TXT records are returned. Non-TXT lines, directives, and
    comments are skipped. Multi-line records joined with ``( )`` are
    collapsed before classification.
    """
    out: List[Record] = []
    lines = content.splitlines()
    origin: Optional[str] = None
    i = 0
    while i < len(lines):
        physical = lines[i]
        text = _strip_comment(physical)
        stripped = text.strip()
        if not stripped:
            i += 1
            continue
        toks = stripped.split()
        if _is_control(toks[0]):
            # $ORIGIN example.com. (apply going forward)
            if toks[0].upper() == "$ORIGIN" and len(toks) >= 2:
                origin = toks[1]
            i += 1
            continue
        # If the line contains an unbalanced '(', consume follow-on
        # lines until balanced.
        if "(" in text and text.count("(") > text.count(")"):
            end_i, joined = _join_multiline(lines, i)
            parsed = _parse_zone_line_block(joined)
            record_line = i + 1
            i = end_i + 1
        else:
            parsed = _parse_zone_line_block(text)
            record_line = i + 1
            i += 1
        if parsed is None:
            continue
        owner_tok, body = parsed
        owner = _canonical_owner(owner_tok, origin)
        kind = _classify(owner, body)
        out.append(Record(
            owner=owner,
            kind=kind,
            value=body,
            line=record_line,
            raw=physical,
        ))
    return out


def parse_bare_text(content: str, kind: RecordKind) -> List[Record]:
    """Treat each non-blank non-comment line as a bare TXT record
    value of the declared kind. Lines may optionally be wrapped in
    double quotes; dnsrec strips a single surrounding pair.
    """
    out: List[Record] = []
    synthetic_owners = {
        RecordKind.SPF: "example.invalid",
        RecordKind.DMARC: "_dmarc.example.invalid",
        RecordKind.DKIM: "selector._domainkey.example.invalid",
    }
    owner = synthetic_owners.get(kind, "example.invalid")
    for i, physical in enumerate(content.splitlines(), start=1):
        stripped = physical.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith(";"):
            continue
        # Strip ONE surrounding pair of double quotes if present.
        if (stripped.startswith('"') and stripped.endswith('"')
                and len(stripped) >= 2):
            body = stripped[1:-1]
        else:
            # Also accept the dig +short format which emits a
            # concatenated series of quoted strings; let the quoted
            # concatenator handle it.
            if '"' in stripped:
                body = _concat_quoted_strings(stripped)
                if not body:
                    body = stripped
            else:
                body = stripped
        out.append(Record(
            owner=owner,
            kind=kind,
            value=body,
            line=i,
            raw=physical,
        ))
    return out


__all__ = [
    "parse_zone_text",
    "parse_bare_text",
]
