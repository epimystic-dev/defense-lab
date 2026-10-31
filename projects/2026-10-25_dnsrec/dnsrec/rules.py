"""Rule registry for dnsrec.

Thirty posture rules on the email-authentication DNS record
surface, each citing the public control it implements. Rule IDs use
the ``SPF-``, ``DMARC-``, and ``DKIM-`` prefixes; the lab-wide shared
surface exposes the combined list as ``ALL_RULES``.

Rules are grounded in these public sources:

  * IETF RFC 7208 - SPF.
  * IETF RFC 7489 - DMARC version 1.
  * IETF RFC 6376 - DomainKeys Identified Mail Signatures.
  * IETF RFC 8463 - A New Cryptographic Signature Method for DKIM
    (Ed25519-SHA256).
  * IETF RFC 1035 - DNS implementation specifics (TXT record quoted-
    string length).
  * NIST SP 800-177 Revision 1 - Trustworthy Email.
  * NIST SP 800-131A - Transition to Stronger Cryptographic Keys
    (RSA minimum effective bit-length).
  * M3AAWG Email Authentication Best Common Practices (public).
  * Public mailbox-provider bulk-sender requirements (Google, Yahoo,
    2024) - cited only where they tighten a floor that an IETF or NIST
    document already names.

The rules capture SHAPE defects visible in the operator's saved file;
they do not test a live mail flow. A clean run is origin-valid, not
verified-safe.
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Set, Tuple

from .types import Finding, Options, Record, RecordKind, Severity


Check = Callable[
    [List[Record], Options],
    List[Finding],
]


@dataclass(frozen=True)
class Rule:
    id: str
    severity: Severity
    title: str
    description: str
    citation: str
    check: Check


# ---------------------------------------------------------------------------
# tag=value helpers (DMARC and DKIM share the semicolon-separated shape)
# ---------------------------------------------------------------------------

def _parse_tag_pairs(value: str) -> List[Tuple[str, str]]:
    """Return a list of (tag, value) pairs for a semicolon-separated
    tag=value body. Whitespace around tags and values is stripped.
    Pairs with no ``=`` are skipped. The order is preserved.
    """
    pairs: List[Tuple[str, str]] = []
    for piece in value.split(";"):
        piece = piece.strip()
        if not piece:
            continue
        if "=" not in piece:
            continue
        tag, val = piece.split("=", 1)
        pairs.append((tag.strip().lower(), val.strip()))
    return pairs


def _tag_map(value: str) -> Dict[str, str]:
    """Last-writer-wins map of tag -> value. DMARC and DKIM both say
    duplicate tags are an error; the linter rules check for that
    separately.
    """
    out: Dict[str, str] = {}
    for k, v in _parse_tag_pairs(value):
        out[k] = v
    return out


# ---------------------------------------------------------------------------
# SPF helpers
# ---------------------------------------------------------------------------

# RFC 7208 section 4.6.4 - mechanisms that count toward the ten-DNS-lookup
# limit: include, a, mx, ptr, exists; and the redirect modifier.
_SPF_LOOKUP_TOKENS = ("include", "a", "mx", "ptr", "exists")


def _spf_mechanisms(value: str) -> List[str]:
    """Return the mechanisms (and modifiers) of an SPF record in file
    order. The "v=spf1" prefix is included; the caller filters it out.
    """
    return value.split()


def _spf_lookup_count(value: str) -> int:
    """Count RFC 7208 section 4.6.4 "DNS-lookup" mechanisms and the
    redirect modifier. Qualifier prefixes (``+``, ``-``, ``~``, ``?``)
    on mechanisms are tolerated.
    """
    count = 0
    for tok in _spf_mechanisms(value):
        t = tok
        if t and t[0] in "+-~?":
            t = t[1:]
        low = t.lower()
        # Mechanisms are either bare ("mx", "a") or name:spec
        # ("include:_spf.example.net", "mx:mail.example.net").
        name = low.split(":", 1)[0].split("/", 1)[0]
        if name in _SPF_LOOKUP_TOKENS:
            count += 1
        elif low.startswith("redirect="):
            count += 1
    return count


def _spf_terminator(value: str) -> Optional[str]:
    """Return the qualifier (``+``, ``-``, ``~``, ``?``) that attaches to
    the ``all`` mechanism, or None if ``all`` is absent.
    """
    for tok in _spf_mechanisms(value):
        t = tok
        q = "+"
        if t and t[0] in "+-~?":
            q = t[0]
            t = t[1:]
        if t.lower() == "all":
            return q
    return None


# ---------------------------------------------------------------------------
# DKIM helpers
# ---------------------------------------------------------------------------

_BASE64_RE = re.compile(r"^[A-Za-z0-9+/=\s]+$")


def _dkim_decode_p(p_value: str) -> Optional[bytes]:
    """Return the decoded bytes of a DKIM p= value, or None on error.
    An empty p= is a revoked key - the caller handles that case before
    reaching this helper.
    """
    stripped = re.sub(r"\s+", "", p_value)
    if not stripped:
        return None
    try:
        return base64.b64decode(stripped, validate=True)
    except (ValueError, base64.binascii.Error):
        return None


def _read_tlv(data: bytes, offset: int) -> Optional[Tuple[int, int, int, bytes]]:
    """Minimal ASN.1 BER TLV reader. Returns (tag, length, next_offset,
    value_bytes) or None on malformed input. Only the tag classes dnsrec
    needs are handled.
    """
    try:
        if offset >= len(data):
            return None
        tag = data[offset]
        offset += 1
        if offset >= len(data):
            return None
        length_byte = data[offset]
        offset += 1
        if length_byte < 0x80:
            length = length_byte
        else:
            n = length_byte & 0x7F
            if n == 0 or n > 4:
                return None
            if offset + n > len(data):
                return None
            length = 0
            for _ in range(n):
                length = (length << 8) | data[offset]
                offset += 1
        if offset + length > len(data):
            return None
        return (tag, length, offset + length, data[offset:offset + length])
    except (IndexError, ValueError):
        return None


_TAG_SEQUENCE = 0x30
_TAG_INTEGER = 0x02
_TAG_BIT_STRING = 0x03


def _rsa_modulus_bits(der: bytes) -> Optional[int]:
    """Extract RSA modulus bit length from either a SubjectPublicKeyInfo
    DER encoding or a raw RSAPublicKey DER encoding (per RFC 3447
    appendix A.1.1 and RFC 5280 section 4.1). Returns None when the
    bytes are not a recognised RSA public-key shape.
    """
    top = _read_tlv(der, 0)
    if top is None or top[0] != _TAG_SEQUENCE:
        return None
    inner = top[3]
    # First TLV inside: either an INTEGER (direct RSAPublicKey) or a
    # SEQUENCE (SubjectPublicKeyInfo's AlgorithmIdentifier).
    first = _read_tlv(inner, 0)
    if first is None:
        return None
    modulus: Optional[bytes] = None
    if first[0] == _TAG_INTEGER:
        modulus = first[3]
    elif first[0] == _TAG_SEQUENCE:
        # SubjectPublicKeyInfo: skip the AlgorithmIdentifier, read the
        # BIT STRING that follows.
        bitstr = _read_tlv(inner, first[2])
        if bitstr is None or bitstr[0] != _TAG_BIT_STRING:
            return None
        content = bitstr[3]
        if not content:
            return None
        # First byte of a BIT STRING is the "unused bits" count.
        content = content[1:]
        inside = _read_tlv(content, 0)
        if inside is None or inside[0] != _TAG_SEQUENCE:
            return None
        mod_tlv = _read_tlv(inside[3], 0)
        if mod_tlv is None or mod_tlv[0] != _TAG_INTEGER:
            return None
        modulus = mod_tlv[3]
    if modulus is None:
        return None
    # Strip ASN.1 leading-zero padding, then count significant bits.
    while modulus and modulus[0] == 0:
        modulus = modulus[1:]
    if not modulus:
        return 0
    bits = len(modulus) * 8
    top_byte = modulus[0]
    mask = 0x80
    leading = 0
    while mask > 0 and (top_byte & mask) == 0:
        leading += 1
        mask >>= 1
    return bits - leading


# ---------------------------------------------------------------------------
# Grouping helpers used by multiple rules
# ---------------------------------------------------------------------------

def _by_owner(records: List[Record], kind: RecordKind) -> Dict[str, List[Record]]:
    out: Dict[str, List[Record]] = {}
    for r in records:
        if r.kind is kind:
            out.setdefault(r.owner, []).append(r)
    return out


def _finding(rule: "Rule", r: Record, message: str, hint: str = "") -> Finding:
    return Finding(
        rule_id=rule.id,
        severity=rule.severity,
        message=message,
        owner=r.owner,
        line=r.line,
        path="",
        hint=hint,
        citation=rule.citation,
    )


# ---------------------------------------------------------------------------
# SPF rules
# ---------------------------------------------------------------------------

def _check_spf_001(records, options):
    out = []
    for owner, group in _by_owner(records, RecordKind.SPF).items():
        if len(group) <= 1:
            continue
        # Report every SPF record after the first at this owner.
        first = group[0]
        for r in group[1:]:
            out.append(_finding(
                _RULES["SPF-001"], r,
                "multiple SPF records at owner " + owner
                + " (" + str(len(group)) + " total; first at line "
                + str(first.line) + ")",
                hint="A domain MUST publish at most one SPF record (RFC 7208 section 3.2). Multiple records cause PermError.",
            ))
    return out


def _check_spf_002(records, options):
    out = []
    for r in records:
        if r.kind is not RecordKind.SPF:
            continue
        if not r.value.lower().startswith("v=spf1"):
            continue
        n = _spf_lookup_count(r.value)
        if n > 10:
            out.append(_finding(
                _RULES["SPF-002"], r,
                "SPF record uses " + str(n)
                + " DNS-lookup mechanisms (ten is the hard cap)",
                hint="RFC 7208 section 4.6.4 caps include / a / mx / ptr / exists / redirect at ten total; receivers return PermError past the cap and treat the message as unauthenticated. Flatten some includes or move low-volume senders to a sub-policy.",
            ))
    return out


def _check_spf_003(records, options):
    out = []
    for r in records:
        if r.kind is not RecordKind.SPF:
            continue
        q = _spf_terminator(r.value)
        if q in ("+", "?"):
            label = "+all" if q == "+" else "?all"
            out.append(_finding(
                _RULES["SPF-003"], r,
                "SPF record ends with " + label + " (permissive default)",
                hint="+all authorises every sender; ?all leaves the policy neutral. RFC 7208 section 4.6.4 defines the qualifiers; -all is the enforcing choice.",
            ))
    return out


def _check_spf_004(records, options):
    out = []
    for r in records:
        if r.kind is not RecordKind.SPF:
            continue
        q = _spf_terminator(r.value)
        if q == "~":
            out.append(_finding(
                _RULES["SPF-004"], r,
                "SPF record ends with ~all (soft fail; M3AAWG recommends -all for enforcement)",
                hint="~all keeps non-matching senders delivered-but-marked. For a mature deployment under DMARC, M3AAWG BCP recommends -all so SPF fail aligns with DMARC enforcement.",
            ))
    return out


def _check_spf_005(records, options):
    out = []
    for r in records:
        if r.kind is not RecordKind.SPF:
            continue
        if _spf_terminator(r.value) is None:
            # Absent all mechanism - but tolerate records that end in a
            # redirect= modifier, which transfers the policy wholesale.
            toks = _spf_mechanisms(r.value)
            if any(t.lower().startswith("redirect=") for t in toks):
                continue
            out.append(_finding(
                _RULES["SPF-005"], r,
                "SPF record has no all mechanism (defaults to neutral)",
                hint="RFC 7208 section 4.7: without an all mechanism, non-matching senders fall through to the default qualifier (neutral). End with -all for enforcement, or ~all for the softer path.",
            ))
    return out


def _check_spf_006(records, options):
    out = []
    for r in records:
        if r.kind is not RecordKind.SPF:
            continue
        for tok in _spf_mechanisms(r.value):
            t = tok
            if t and t[0] in "+-~?":
                t = t[1:]
            low = t.lower()
            name = low.split(":", 1)[0]
            if name == "ptr":
                out.append(_finding(
                    _RULES["SPF-006"], r,
                    "SPF record uses the deprecated ptr mechanism",
                    hint="RFC 7208 section 5.5: ptr SHOULD NOT be used because it is slow, unreliable and places load on arpa name servers. Replace with ip4 / ip6 ranges or include: references.",
                ))
                break
    return out


def _check_spf_007(records, options):
    out = []
    for r in records:
        if r.kind is not RecordKind.SPF:
            continue
        # The raw line can hide the actual per-string length because the
        # parser joined concatenated quoted strings. We measure the
        # logical SPF value length and flag when it would require more
        # than one 255-byte quoted segment, which the operator must
        # author explicitly per RFC 1035.
        if len(r.value) > 255:
            out.append(_finding(
                _RULES["SPF-007"], r,
                "SPF record logical length " + str(len(r.value))
                + " bytes exceeds a single 255-byte TXT quoted string",
                hint="RFC 1035 section 3.3.14 limits each TXT quoted string to 255 octets. Longer bodies must be authored as adjacent quoted strings; most zone editors emit the correct syntax automatically, but check that the published record is a concatenation and not a single oversize string.",
            ))
    return out


def _check_spf_008(records, options):
    out = []
    for r in records:
        if r.kind is not RecordKind.SPF:
            continue
        # Only flag records that were classified SPF by owner-shape but
        # whose body does not open with v=spf1. The classifier labels
        # non-SPF-looking bodies as OTHER, so a hit here means the
        # operator intended SPF but mis-spelt the version tag.
        if not r.value.lower().startswith("v=spf1"):
            out.append(_finding(
                _RULES["SPF-008"], r,
                "SPF-shaped record does not begin with v=spf1",
                hint="RFC 7208 section 4.5: every SPF record MUST begin with the token v=spf1 (case-insensitive). Receivers ignore records that do not.",
            ))
    return out


def _check_spf_009(records, options):
    out = []
    for r in records:
        if r.kind is not RecordKind.SPF:
            continue
        toks = _spf_mechanisms(r.value)
        for tok in toks:
            t = tok
            q = "+"
            if t and t[0] in "+-~?":
                q = t[0]
                t = t[1:]
            if q != "+":
                continue
            low = t.lower()
            if low == "ip4:0.0.0.0/0" or low == "ip6:::/0":
                out.append(_finding(
                    _RULES["SPF-009"], r,
                    "SPF record contains any-source wildcard "
                    + t,
                    hint="Authorising every address of the Internet negates the point of SPF; NIST SP 800-177 section 4.6.1 names explicit allowlists as the required practice.",
                ))
                break
    return out


def _check_spf_010(records, options):
    # RFC 7208 Appendix A ABNF:
    #     record  = version terms *SP
    #     version = "v=spf1"
    #     terms   = *( 1*SP ( directive / modifier ) )
    # The version section MUST be either the entire record body or be
    # followed by at least one SP (0x20) or HTAB (0x09) before any
    # further term. A record body such as ``v=spf1-all`` or
    # ``v=spf1include:_spf.example.com -all`` is malformed: receivers
    # discard it per section 4.5 because the version does not
    # terminate at the expected boundary. Today an operator who drops
    # the space before ``-all`` sees SPF-005 ("no all mechanism") and
    # imagines they need to add ``-all`` - the ``-all`` they wrote has
    # been swallowed into the version run of characters. Worse, a
    # dropped space before an ``include`` mechanism silences every
    # SPF rule and the record passes clean.
    out = []
    for r in records:
        if r.kind is not RecordKind.SPF:
            continue
        v = r.value
        if not v.lower().startswith("v=spf1"):
            # SPF-008 handles the wrong-version case.
            continue
        if len(v) == 6:
            # ``v=spf1`` alone (empty terms list) is valid per the
            # ABNF: ``*SP`` after ``terms`` permits zero trailing
            # whitespace.
            continue
        if v[6] in (" ", "\t"):
            continue
        trailer = v[6:]
        trailer_preview = trailer if len(trailer) <= 32 else trailer[:29] + "..."
        out.append(_finding(
            _RULES["SPF-010"], r,
            "SPF version section v=spf1 is not followed by whitespace"
            + " (saw: v=spf1" + trailer_preview + ")",
            hint="RFC 7208 Appendix A ABNF requires v=spf1 to be either the whole record body or to be followed by whitespace before any mechanism or modifier. Receivers discard the record when the version section does not terminate, so no SPF policy is applied at all; insert a space between v=spf1 and the first term.",
        ))
    return out


# ---------------------------------------------------------------------------
# DMARC rules
# ---------------------------------------------------------------------------

_DMARC_POLICY_VALUES = {"none", "quarantine", "reject"}


def _check_dmarc_001(records, options):
    out = []
    for r in records:
        if r.kind is not RecordKind.DMARC:
            continue
        tags = _tag_map(r.value)
        p = tags.get("p", "").lower()
        if p == "none":
            out.append(_finding(
                _RULES["DMARC-001"], r,
                "DMARC policy is p=none (monitor-only, non-enforcing)",
                hint="RFC 7489 section 6.3: p=none is diagnostic only. NIST SP 800-177 section 4.6.2 names p=quarantine or p=reject as the enforcement baseline, and major mailbox providers now require quarantine or reject for bulk senders.",
            ))
    return out


def _check_dmarc_002(records, options):
    out = []
    for r in records:
        if r.kind is not RecordKind.DMARC:
            continue
        tags = _tag_map(r.value)
        p = tags.get("p", "").lower()
        if p == "quarantine":
            out.append(_finding(
                _RULES["DMARC-002"], r,
                "DMARC policy is p=quarantine (intermediate; recommend p=reject)",
                hint="RFC 7489 section 6.3 permits quarantine as an intermediate posture. NIST SP 800-177 section 4.6.2 names p=reject as the mature-deployment target.",
            ))
    return out


def _check_dmarc_003(records, options):
    out = []
    for r in records:
        if r.kind is not RecordKind.DMARC:
            continue
        if not r.value.lower().startswith("v=dmarc1"):
            # DMARC-004 will fire on this; skip DMARC-003 to avoid
            # double-reporting.
            continue
        tags = _tag_map(r.value)
        if "p" not in tags:
            out.append(_finding(
                _RULES["DMARC-003"], r,
                "DMARC record is missing the required p= tag",
                hint="RFC 7489 section 6.3: p= is a required tag. A record without p= is treated as missing by receivers.",
            ))
    return out


def _check_dmarc_004(records, options):
    out = []
    for r in records:
        if r.kind is not RecordKind.DMARC:
            continue
        if not r.value.lower().startswith("v=dmarc1"):
            out.append(_finding(
                _RULES["DMARC-004"], r,
                "DMARC-shaped record does not begin with v=DMARC1",
                hint="RFC 7489 section 6.3: every DMARC record MUST open with v=DMARC1 (case-insensitive, no whitespace between v= and DMARC1).",
            ))
    return out


def _check_dmarc_005(records, options):
    out = []
    for r in records:
        if r.kind is not RecordKind.DMARC:
            continue
        tags = _tag_map(r.value)
        pct = tags.get("pct")
        if pct is None:
            continue
        raw = pct.strip()
        try:
            n = int(raw)
        except ValueError:
            # Unparseable integer: receivers ignore the tag and fall back
            # to the pct=100 default, silently converting an intended
            # partial rollout into full enforcement. Parity with the
            # SSH-006 / SSH-007 / SSH-008 pattern of flagging malformed
            # values at the same rule.
            out.append(_finding(
                _RULES["DMARC-005"], r,
                "DMARC pct=" + raw
                + " is not a plain-text integer (receivers ignore the"
                + " tag and fall back to pct=100)",
                hint="RFC 7489 section 6.3 requires pct to be a plain-text integer between 0 and 100 inclusive. An unparseable value is ignored by receivers, so the intended partial-rollout fraction is lost.",
            ))
            continue
        if not (0 <= n <= 100):
            out.append(_finding(
                _RULES["DMARC-005"], r,
                "DMARC pct=" + str(n)
                + " is outside the 0..100 range (receivers ignore the"
                + " tag and fall back to pct=100)",
                hint="RFC 7489 section 6.3 requires pct to be a plain-text integer between 0 and 100 inclusive. An out-of-range value is ignored by receivers, so the intended partial-rollout fraction is lost.",
            ))
            continue
        if 0 <= n < 100:
            out.append(_finding(
                _RULES["DMARC-005"], r,
                "DMARC pct=" + str(n) + " (partial deployment; only "
                + str(n) + " percent of failing mail is enforced)",
                hint="RFC 7489 section 6.3 defines pct as the fraction of failing messages the receiver applies the policy to. pct<100 is a rollout tool, not an end state.",
            ))
    return out


def _check_dmarc_006(records, options):
    out = []
    for r in records:
        if r.kind is not RecordKind.DMARC:
            continue
        tags = _tag_map(r.value)
        adkim = tags.get("adkim", "r").lower()
        if adkim == "r":
            out.append(_finding(
                _RULES["DMARC-006"], r,
                "DMARC adkim=r (relaxed DKIM alignment is the default)",
                hint="RFC 7489 section 6.3: strict alignment (adkim=s) ties the DKIM d= domain to the From: header domain exactly; relaxed permits a sub-domain match. For high-value domains, strict alignment is harder to abuse via sub-domain take-over.",
            ))
    return out


def _check_dmarc_007(records, options):
    out = []
    for r in records:
        if r.kind is not RecordKind.DMARC:
            continue
        tags = _tag_map(r.value)
        aspf = tags.get("aspf", "r").lower()
        if aspf == "r":
            out.append(_finding(
                _RULES["DMARC-007"], r,
                "DMARC aspf=r (relaxed SPF alignment is the default)",
                hint="RFC 7489 section 6.3: strict SPF alignment (aspf=s) requires the SPF-authenticated domain to match the From: header domain exactly. Relaxed permits a sub-domain match.",
            ))
    return out


def _check_dmarc_008(records, options):
    out = []
    for r in records:
        if r.kind is not RecordKind.DMARC:
            continue
        tags = _tag_map(r.value)
        if "rua" not in tags or not tags["rua"].strip():
            out.append(_finding(
                _RULES["DMARC-008"], r,
                "DMARC record has no rua= aggregate reporting URI",
                hint="Without rua=, the domain owner has no visibility into which senders are failing authentication. M3AAWG BCP and NIST SP 800-177 section 4.6.2 both name rua= as required operational hygiene.",
            ))
    return out


def _check_dmarc_009(records, options):
    out = []
    _rank = {"none": 0, "quarantine": 1, "reject": 2}
    for r in records:
        if r.kind is not RecordKind.DMARC:
            continue
        tags = _tag_map(r.value)
        p = tags.get("p", "").lower()
        sp = tags.get("sp")
        if sp is None:
            continue
        sp = sp.lower()
        if p not in _rank or sp not in _rank:
            continue
        if _rank[sp] < _rank[p]:
            out.append(_finding(
                _RULES["DMARC-009"], r,
                "DMARC sp=" + sp + " is weaker than p=" + p
                + " (sub-domain policy loosens the parent)",
                hint="RFC 7489 section 6.3: a sub-domain policy weaker than the parent leaves sub-domains available for look-alike abuse. Set sp= to match or strengthen p=.",
            ))
    return out


def _check_dmarc_010(records, options):
    out = []
    for r in records:
        if r.kind is not RecordKind.DMARC:
            continue
        owner = r.owner.lower()
        if not owner.startswith("_dmarc.") and owner != "_dmarc":
            out.append(_finding(
                _RULES["DMARC-010"], r,
                "DMARC record is not published at _dmarc.<domain> (owner: "
                + owner + ")",
                hint="RFC 7489 section 6.1: receivers look up DMARC at _dmarc.<org-domain>. A record anywhere else is invisible to validators.",
            ))
    return out


def _check_dmarc_011(records, options):
    # RFC 7489 section 6.3 defines p= as taking exactly one of three
    # values: none, quarantine, reject. Section 6.6.3 is explicit that
    # a receiver which cannot parse a required tag MUST NOT apply the
    # DMARC mechanism to the message, so a typo like ``p=rejects`` or
    # ``p=banana`` causes receivers to skip DMARC entirely. The operator
    # believes they published a reject policy; in practice they have no
    # DMARC posture at all. Parallels DMARC-005 (invalid pct= value) in
    # flagging a shape defect that silently defaults to the unenforced
    # state. Disjoint from DMARC-001 and DMARC-002 by construction (both
    # fire only on valid policy values); gated by the v=DMARC1 version
    # check so DMARC-004 handles the wrong-version case alone; gated by
    # presence of p= so DMARC-003 handles the missing-p= case alone.
    out = []
    for r in records:
        if r.kind is not RecordKind.DMARC:
            continue
        if not r.value.lower().startswith("v=dmarc1"):
            continue
        tags = _tag_map(r.value)
        p = tags.get("p")
        if p is None:
            continue
        if p.strip().lower() not in _DMARC_POLICY_VALUES:
            out.append(_finding(
                _RULES["DMARC-011"], r,
                "DMARC p=" + p
                + " is not a valid policy value (expected none, quarantine, or reject)",
                hint="RFC 7489 section 6.3 defines p= as taking exactly one of none, quarantine, or reject. Per section 6.6.3, a receiver that cannot parse the p= tag MUST NOT apply the DMARC mechanism; the record is skipped entirely, so the intended policy has no effect at any receiver.",
            ))
    return out


# ---------------------------------------------------------------------------
# DKIM rules
# ---------------------------------------------------------------------------

_DKIM_VALID_KEY_TYPES = {"rsa", "ed25519"}


def _check_dkim_001(records, options):
    out = []
    for r in records:
        if r.kind is not RecordKind.DKIM:
            continue
        tags = _tag_map(r.value)
        v = tags.get("v")
        # RFC 6376 section 3.6.1: the v= tag MUST be the first tag if
        # present, and MUST have the value "DKIM1". It is also permitted
        # to be absent (defaulting to DKIM1), so a missing v= is not an
        # error in itself.
        if v is not None and v.strip().lower() != "dkim1":
            out.append(_finding(
                _RULES["DKIM-001"], r,
                "DKIM record v= tag is not DKIM1 (saw: " + v + ")",
                hint="RFC 6376 section 3.6.1: when the v= tag is present it MUST have the value DKIM1.",
            ))
    return out


def _check_dkim_002(records, options):
    out = []
    for r in records:
        if r.kind is not RecordKind.DKIM:
            continue
        tags = _tag_map(r.value)
        k = tags.get("k")
        if k is None:
            continue
        kl = k.strip().lower()
        if kl not in _DKIM_VALID_KEY_TYPES:
            out.append(_finding(
                _RULES["DKIM-002"], r,
                "DKIM key type k=" + k
                + " is not a recognised algorithm (expected rsa or ed25519)",
                hint="RFC 6376 section 3.6.1 defines rsa; RFC 8463 adds ed25519. Any other value is ignored by receivers.",
            ))
    return out


def _check_dkim_003(records, options):
    out = []
    for r in records:
        if r.kind is not RecordKind.DKIM:
            continue
        tags = _tag_map(r.value)
        if "p" not in tags:
            continue
        p = tags["p"].strip()
        if not p:
            out.append(_finding(
                _RULES["DKIM-003"], r,
                "DKIM record p= is empty (key revoked)",
                hint="RFC 6376 section 3.6.1: an empty p= value signals that this key has been revoked. If the selector is still in use for signing, publishing an empty p= stops verification entirely.",
            ))
    return out


def _check_dkim_004(records, options):
    out = []
    for r in records:
        if r.kind is not RecordKind.DKIM:
            continue
        tags = _tag_map(r.value)
        p = tags.get("p", "").strip()
        if not p:
            continue
        k = tags.get("k", "rsa").strip().lower()
        if k != "rsa":
            # Only RSA has a bit-length concern in this rule-set; Ed25519
            # is a fixed-size key.
            continue
        der = _dkim_decode_p(p)
        if der is None:
            continue
        bits = _rsa_modulus_bits(der)
        if bits is None:
            continue
        if bits < 2048:
            out.append(_finding(
                _RULES["DKIM-004"], r,
                "DKIM RSA public key is " + str(bits)
                + " bits (NIST SP 800-131A deprecates below 2048)",
                hint="RFC 6376 section 3.3.3 permits keys as small as 512 bits; NIST SP 800-131A and M3AAWG BCP both deprecate RSA keys below 2048. Rotate the selector to a new 2048-bit (or stronger) key.",
            ))
    return out


def _check_dkim_005(records, options):
    out = []
    for r in records:
        if r.kind is not RecordKind.DKIM:
            continue
        tags = _tag_map(r.value)
        t = tags.get("t")
        if t is None:
            continue
        flags = {s.strip().lower() for s in t.split(":") if s.strip()}
        if "y" in flags:
            out.append(_finding(
                _RULES["DKIM-005"], r,
                "DKIM record is in testing mode (t=y)",
                hint="RFC 6376 section 3.6.1: in testing mode, verifiers MUST NOT treat messages differently from unsigned mail. Testing selectors left live in production make DKIM a no-op for that selector.",
            ))
    return out


def _check_dkim_006(records, options):
    out = []
    for r in records:
        if r.kind is not RecordKind.DKIM:
            continue
        tags = _tag_map(r.value)
        if "g" in tags:
            out.append(_finding(
                _RULES["DKIM-006"], r,
                "DKIM record carries the obsolete g= granularity tag",
                hint="RFC 6376 section 3.6.1 removed the g= tag that was present in the older DomainKeys / RFC 4871 standard. The tag is harmless but marks a stale record definition.",
            ))
    return out


def _check_dkim_007(records, options):
    out = []
    for r in records:
        if r.kind is not RecordKind.DKIM:
            continue
        tags = _tag_map(r.value)
        p = tags.get("p", "").strip()
        if not p:
            continue
        stripped = re.sub(r"\s+", "", p)
        if not _BASE64_RE.match(stripped):
            out.append(_finding(
                _RULES["DKIM-007"], r,
                "DKIM p= value contains characters that are not valid base64",
                hint="RFC 6376 section 3.6.1: p= MUST be a base64-encoded public key per the alphabet in RFC 4648. A stray space, line continuation marker, or paste artefact invalidates the whole key.",
            ))
            continue
        if _dkim_decode_p(p) is None:
            out.append(_finding(
                _RULES["DKIM-007"], r,
                "DKIM p= value is not decodable as base64 (padding or length error)",
                hint="RFC 6376 section 3.6.1: the base64 payload must round-trip through RFC 4648. Check that your zone editor did not strip a trailing = padding character.",
            ))
    return out


def _check_dkim_008(records, options):
    out = []
    for r in records:
        if r.kind is not RecordKind.DKIM:
            continue
        owner = r.owner.lower()
        if "_domainkey" not in owner:
            out.append(_finding(
                _RULES["DKIM-008"], r,
                "DKIM record is not published under _domainkey (owner: "
                + owner + ")",
                hint="RFC 6376 section 3.6.2.1: receivers look up DKIM keys at <selector>._domainkey.<signing-domain>. A record anywhere else is invisible.",
            ))
    return out


def _check_dkim_009(records, options):
    # RFC 6376 section 3.6.1 marks p= as REQUIRED. A record with p=
    # entirely absent is malformed; receivers have no public key and
    # cannot verify signatures from this selector. Distinct from
    # DKIM-003 (empty p=, which is an explicit revocation signal) -
    # the two cases are RFC-different and operator-different (a
    # missing p= is usually a zone-editor dropped-field accident,
    # whereas an empty p= is an intentional revocation).
    out = []
    for r in records:
        if r.kind is not RecordKind.DKIM:
            continue
        tags = _tag_map(r.value)
        if "p" not in tags:
            out.append(_finding(
                _RULES["DKIM-009"], r,
                "DKIM record is missing the required p= tag",
                hint="RFC 6376 section 3.6.1: p= is a REQUIRED tag. Without it the record has no public key, so receivers cannot verify any signature from this selector; the signed mail is treated as unsigned. If the key is intentionally retired, publish p= with an empty value (DKIM-003) to signal revocation rather than removing the tag.",
            ))
    return out


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

def _rule(id_, severity, title, description, citation, check):
    return Rule(id=id_, severity=severity, title=title,
                description=description, citation=citation, check=check)


REGISTRY: List[Rule] = [
    _rule(
        "SPF-001", Severity.HIGH,
        "multiple SPF records at one owner",
        "A domain SHOULD publish at most one SPF record; multiple cause PermError.",
        "RFC 7208 section 3.2",
        _check_spf_001,
    ),
    _rule(
        "SPF-002", Severity.HIGH,
        "SPF record exceeds ten DNS lookups",
        "The include / a / mx / ptr / exists mechanisms and the redirect modifier together cap at ten lookups.",
        "RFC 7208 section 4.6.4",
        _check_spf_002,
    ),
    _rule(
        "SPF-003", Severity.HIGH,
        "SPF record ends with +all or ?all",
        "+all authorises every sender; ?all leaves the policy neutral.",
        "RFC 7208 section 4.6.4",
        _check_spf_003,
    ),
    _rule(
        "SPF-004", Severity.MEDIUM,
        "SPF record ends with ~all",
        "~all is soft-fail; M3AAWG BCP recommends -all for enforcement.",
        "M3AAWG Email Authentication Best Common Practices",
        _check_spf_004,
    ),
    _rule(
        "SPF-005", Severity.HIGH,
        "SPF record has no all mechanism",
        "Without all, non-matching senders fall through to neutral (RFC 7208 section 4.7).",
        "RFC 7208 section 4.7",
        _check_spf_005,
    ),
    _rule(
        "SPF-006", Severity.MEDIUM,
        "SPF record uses the deprecated ptr mechanism",
        "RFC 7208 section 5.5 says ptr SHOULD NOT be used.",
        "RFC 7208 section 5.5",
        _check_spf_006,
    ),
    _rule(
        "SPF-007", Severity.INFO,
        "SPF record logical length exceeds a single 255-byte TXT quoted string",
        "RFC 1035 section 3.3.14 limits each TXT quoted string to 255 octets.",
        "RFC 1035 section 3.3.14",
        _check_spf_007,
    ),
    _rule(
        "SPF-008", Severity.HIGH,
        "SPF-shaped record does not begin with v=spf1",
        "Receivers ignore records that do not open with v=spf1.",
        "RFC 7208 section 4.5",
        _check_spf_008,
    ),
    _rule(
        "SPF-009", Severity.MEDIUM,
        "SPF record contains an any-source wildcard",
        "Authorising 0.0.0.0/0 or ::/0 negates the point of SPF.",
        "NIST SP 800-177 section 4.6.1",
        _check_spf_009,
    ),
    _rule(
        "SPF-010", Severity.HIGH,
        "SPF version section is not followed by whitespace",
        "RFC 7208 Appendix A requires v=spf1 to be either the whole record or followed by whitespace; a record like v=spf1-all or v=spf1include:... is discarded by receivers.",
        "RFC 7208 section 4.5; RFC 7208 Appendix A",
        _check_spf_010,
    ),
    _rule(
        "DMARC-001", Severity.HIGH,
        "DMARC policy is p=none",
        "p=none is monitor-only; NIST SP 800-177 section 4.6.2 names p=quarantine / p=reject as the enforcement baseline.",
        "RFC 7489 section 6.3; NIST SP 800-177 section 4.6.2",
        _check_dmarc_001,
    ),
    _rule(
        "DMARC-002", Severity.MEDIUM,
        "DMARC policy is p=quarantine",
        "quarantine is intermediate; reject is the mature-deployment target.",
        "NIST SP 800-177 section 4.6.2",
        _check_dmarc_002,
    ),
    _rule(
        "DMARC-003", Severity.HIGH,
        "DMARC record is missing the required p= tag",
        "RFC 7489 section 6.3: p= is a required tag.",
        "RFC 7489 section 6.3",
        _check_dmarc_003,
    ),
    _rule(
        "DMARC-004", Severity.HIGH,
        "DMARC-shaped record does not begin with v=DMARC1",
        "Every DMARC record MUST open with v=DMARC1.",
        "RFC 7489 section 6.3",
        _check_dmarc_004,
    ),
    _rule(
        "DMARC-005", Severity.HIGH,
        "DMARC pct= tag is partial, malformed, or out of range",
        "pct<100 is a rollout tool, not an end state; a non-integer or out-of-range pct is ignored by receivers and silently defaults to 100.",
        "RFC 7489 section 6.3",
        _check_dmarc_005,
    ),
    _rule(
        "DMARC-006", Severity.MEDIUM,
        "DMARC adkim=r (relaxed DKIM alignment)",
        "Strict DKIM alignment (adkim=s) is harder to bypass via sub-domain take-over.",
        "RFC 7489 section 6.3",
        _check_dmarc_006,
    ),
    _rule(
        "DMARC-007", Severity.MEDIUM,
        "DMARC aspf=r (relaxed SPF alignment)",
        "Strict SPF alignment (aspf=s) requires an exact From: domain match.",
        "RFC 7489 section 6.3",
        _check_dmarc_007,
    ),
    _rule(
        "DMARC-008", Severity.HIGH,
        "DMARC record has no rua= aggregate reporting URI",
        "Without rua= the operator has no visibility into failures.",
        "M3AAWG Email Authentication BCP; NIST SP 800-177 section 4.6.2",
        _check_dmarc_008,
    ),
    _rule(
        "DMARC-009", Severity.HIGH,
        "DMARC sp= is weaker than p=",
        "A looser sub-domain policy leaves sub-domains open to look-alike abuse.",
        "RFC 7489 section 6.3",
        _check_dmarc_009,
    ),
    _rule(
        "DMARC-010", Severity.HIGH,
        "DMARC record is not published at _dmarc.<domain>",
        "Receivers look up DMARC at _dmarc.<org-domain>.",
        "RFC 7489 section 6.1",
        _check_dmarc_010,
    ),
    _rule(
        "DMARC-011", Severity.HIGH,
        "DMARC p= value is not none|quarantine|reject",
        "An unrecognised p= value causes receivers to skip DMARC entirely per RFC 7489 section 6.6.3; the intended policy has no effect.",
        "RFC 7489 section 6.3; RFC 7489 section 6.6.3",
        _check_dmarc_011,
    ),
    _rule(
        "DKIM-001", Severity.HIGH,
        "DKIM record v= is present but is not DKIM1",
        "The v= tag MUST be DKIM1 when present.",
        "RFC 6376 section 3.6.1",
        _check_dkim_001,
    ),
    _rule(
        "DKIM-002", Severity.HIGH,
        "DKIM key type k= is not rsa or ed25519",
        "RFC 6376 defines rsa; RFC 8463 adds ed25519. Other values are ignored.",
        "RFC 6376 section 3.6.1; RFC 8463",
        _check_dkim_002,
    ),
    _rule(
        "DKIM-003", Severity.HIGH,
        "DKIM record p= is empty (key revoked)",
        "An empty p= signals the key is revoked.",
        "RFC 6376 section 3.6.1",
        _check_dkim_003,
    ),
    _rule(
        "DKIM-004", Severity.HIGH,
        "DKIM RSA public key is below 2048 bits",
        "NIST SP 800-131A deprecates RSA keys below 2048 bits.",
        "NIST SP 800-131A; M3AAWG Email Authentication BCP",
        _check_dkim_004,
    ),
    _rule(
        "DKIM-005", Severity.MEDIUM,
        "DKIM record is in testing mode (t=y)",
        "In testing mode, verifiers treat messages like unsigned mail.",
        "RFC 6376 section 3.6.1",
        _check_dkim_005,
    ),
    _rule(
        "DKIM-006", Severity.INFO,
        "DKIM record carries the obsolete g= granularity tag",
        "RFC 6376 removed the g= tag that was present in RFC 4871 / DomainKeys.",
        "RFC 6376 section 3.6.1",
        _check_dkim_006,
    ),
    _rule(
        "DKIM-007", Severity.HIGH,
        "DKIM p= value is not valid base64",
        "The base64 payload must round-trip through RFC 4648.",
        "RFC 6376 section 3.6.1; RFC 4648",
        _check_dkim_007,
    ),
    _rule(
        "DKIM-008", Severity.HIGH,
        "DKIM record is not published under _domainkey",
        "Receivers look up DKIM at <selector>._domainkey.<signing-domain>.",
        "RFC 6376 section 3.6.2.1",
        _check_dkim_008,
    ),
    _rule(
        "DKIM-009", Severity.HIGH,
        "DKIM record is missing the required p= tag",
        "RFC 6376 section 3.6.1 marks p= as REQUIRED; a record without p= has no public key available and all signatures from the selector are treated as unsigned by receivers.",
        "RFC 6376 section 3.6.1",
        _check_dkim_009,
    ),
]


# Fast lookup used by _finding().
_RULES: Dict[str, Rule] = {r.id: r for r in REGISTRY}


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------

def run_all(
    records: List[Record], text: str, path: str, options: Options,
) -> List[Finding]:
    """Execute every enabled rule against the parsed records. Attach the
    source ``path`` to each Finding and apply the ``--only`` / ``--disable``
    / ``--include-info`` filters.
    """
    out: List[Finding] = []
    for rule in REGISTRY:
        if not options.rule_enabled(rule.id):
            continue
        if rule.severity is Severity.INFO:
            if not (options.include_info or options.strict):
                continue
        try:
            findings = rule.check(records, options)
        except Exception as e:
            # A rule bug should never crash the scanner; surface as an
            # internal HIGH finding so the operator sees that the scan
            # was incomplete.
            findings = [Finding(
                rule_id=rule.id,
                severity=Severity.HIGH,
                message="rule crashed: " + repr(e),
                owner="",
                line=0,
                path=path,
                hint="This is a dnsrec bug. Please report it with the input that triggered it.",
                citation=rule.citation,
            )]
        for f in findings:
            if f.path:
                out.append(f)
            else:
                out.append(Finding(
                    rule_id=f.rule_id,
                    severity=f.severity,
                    message=f.message,
                    owner=f.owner,
                    line=f.line,
                    path=path,
                    hint=f.hint,
                    citation=f.citation,
                ))
    return out


__all__ = ["REGISTRY", "Rule", "Check", "run_all"]
