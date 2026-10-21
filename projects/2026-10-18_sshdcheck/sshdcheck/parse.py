"""File-shape parser for sshdcheck.

An ``sshd_config`` file is a line-oriented keyword-value configuration
(see sshd_config(5)). This parser:

  * strips comments (``#`` to end of line) and blank lines,
  * tokenises each non-blank line into (keyword, arguments-string),
  * folds the keyword to its canonical case (sshd_config is
    case-insensitive for keywords),
  * records the physical line number so a finding can anchor on it,
  * surfaces an ``Include`` directive as a Directive with the include
    glob as its value - this tool does NOT follow includes, since the
    operator-saved file is the only trusted input.

The parser returns a list of ``Directive`` records, in file order. A
rule reads the list (and a small by-keyword index) and emits findings.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple


# Canonical case for the subset of sshd_config keywords sshdcheck's rules
# address. The sshd_config file is case-insensitive for keywords; this
# table lets reporting show the keyword as sshd_config(5) spells it.
_CANONICAL: Dict[str, str] = {
    "allowtcpforwarding": "AllowTcpForwarding",
    "banner": "Banner",
    "ciphers": "Ciphers",
    "clientaliveinterval": "ClientAliveInterval",
    "clientalivecountmax": "ClientAliveCountMax",
    "hostbasedauthentication": "HostbasedAuthentication",
    "ignorerhosts": "IgnoreRhosts",
    "include": "Include",
    "kexalgorithms": "KexAlgorithms",
    "logingracetime": "LoginGraceTime",
    "loglevel": "LogLevel",
    "macs": "MACs",
    "match": "Match",
    "maxauthtries": "MaxAuthTries",
    "passwordauthentication": "PasswordAuthentication",
    "permitemptypasswords": "PermitEmptyPasswords",
    "permitrootlogin": "PermitRootLogin",
    "protocol": "Protocol",
    "pubkeyauthentication": "PubkeyAuthentication",
    "usepam": "UsePAM",
    "x11forwarding": "X11Forwarding",
}


def canonical_keyword(raw: str) -> str:
    """Return the canonical case for a keyword, or the raw spelling if
    we have no entry for it.
    """
    return _CANONICAL.get(raw.lower(), raw)


@dataclass(frozen=True)
class Directive:
    """One non-blank, non-comment line parsed from sshd_config."""

    keyword: str          # canonical case (e.g. "PermitRootLogin")
    value: str            # everything after the keyword, whitespace-trimmed
    line: int             # 1-based line number in the source file
    raw: str              # the physical line, with its newline stripped
    in_match: bool        # True if the line appears inside a Match block


def parse_text(content: str) -> List[Directive]:
    """Parse the full text of an sshd_config file into Directives."""
    out: List[Directive] = []
    in_match = False
    for i, physical in enumerate(content.splitlines(), start=1):
        line = physical
        # sshd_config does not define a line-continuation escape; a
        # trailing backslash is not a continuation and is preserved
        # verbatim in the keyword's value.
        line_stripped = line.strip()
        if not line_stripped or line_stripped.startswith("#"):
            continue
        # Strip an inline comment, but only when preceded by whitespace -
        # a '#' inside a quoted value is not a comment, so we take the
        # conservative path: the OpenSSH parser itself treats '#' only
        # at the start of a line as a comment. We follow that.
        # Tokenise on whitespace: first token is the keyword, the rest
        # is the value (joined with single spaces preserved).
        parts = line_stripped.split(None, 1)
        if not parts:
            continue
        raw_keyword = parts[0]
        value = parts[1].strip() if len(parts) == 2 else ""
        keyword = canonical_keyword(raw_keyword)
        # Match blocks: once seen, every subsequent directive is scoped
        # to that match - the sshdcheck rules apply to the pre-Match
        # (global) directives; Match-scoped overrides are reported but
        # not re-evaluated to avoid false confidence.
        if keyword == "Match":
            in_match = True
            out.append(Directive(keyword, value, i, line, False))
            continue
        out.append(Directive(keyword, value, i, line, in_match))
    return out


def index_by_keyword(
    directives: List[Directive],
) -> Dict[str, List[Directive]]:
    """Return canonical-keyword -> ordered list of directives.

    The last global (non-Match) directive wins per sshd_config
    semantics; rules use the first global entry so a finding anchors
    on the earliest declaration (easier to grep).
    """
    idx: Dict[str, List[Directive]] = {}
    for d in directives:
        idx.setdefault(d.keyword, []).append(d)
    return idx


def first_global(
    index: Dict[str, List[Directive]], keyword: str
) -> Optional[Directive]:
    """First directive of the given canonical keyword outside any Match
    block, or None.
    """
    for d in index.get(keyword, []):
        if not d.in_match:
            return d
    return None


def effective_global(
    index: Dict[str, List[Directive]], keyword: str
) -> Optional[Directive]:
    """Last global directive for the given keyword (what sshd actually
    applies at the global scope). None when the keyword is absent at
    the global scope.
    """
    last: Optional[Directive] = None
    for d in index.get(keyword, []):
        if not d.in_match:
            last = d
    return last


def split_csv_or_space(value: str) -> List[str]:
    """Split an sshd_config list value. The algorithm fields (Ciphers,
    MACs, KexAlgorithms) are documented as comma-separated, but
    operators sometimes write them space-separated; we accept both.
    """
    # Split on commas first; then on whitespace within each part.
    pieces: List[str] = []
    for piece in value.split(","):
        for tok in piece.split():
            if tok:
                pieces.append(tok)
    return pieces


def value_truthy(value: str) -> Optional[bool]:
    """Return True / False / None for an sshd_config yes-no value.

    sshd_config accepts ``yes`` / ``no`` (case-insensitive) and a few
    keyword-specific extensions. Unknown values return None.
    """
    v = value.strip().lower()
    if v == "yes":
        return True
    if v == "no":
        return False
    return None


__all__ = [
    "Directive",
    "parse_text",
    "canonical_keyword",
    "index_by_keyword",
    "first_global",
    "effective_global",
    "split_csv_or_space",
    "value_truthy",
]
