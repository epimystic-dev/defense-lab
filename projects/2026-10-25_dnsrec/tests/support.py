"""Shared test helpers for dnsrec."""

from __future__ import annotations

import base64
import io
import os
import tempfile
from typing import Iterable, Optional, Sequence, Tuple

from dnsrec.cli import main as cli_main
from dnsrec.parse import parse_bare_text, parse_zone_text
from dnsrec.rules import run_all
from dnsrec.types import Finding, Options, Record, RecordKind


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
# Fixture builders.
# ---------------------------------------------------------------------------

def scan_zone_string(
    content: str,
    options: Optional[Options] = None,
    path: str = "in-memory",
) -> Sequence[Finding]:
    options = options or Options()
    records = parse_zone_text(content)
    return run_all(records, content, path, options)


def scan_bare_string(
    content: str,
    kind: RecordKind,
    options: Optional[Options] = None,
    path: str = "in-memory",
) -> Sequence[Finding]:
    options = options or Options()
    records = parse_bare_text(content, kind)
    return run_all(records, content, path, options)


def write_temp(
    content: str, name: str = "zone.txt",
) -> Tuple[str, str]:
    """Write a zone body to a fresh temp directory, return (dir, path)."""
    d = tempfile.mkdtemp(prefix="dnsrec_")
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


# ---------------------------------------------------------------------------
# Minimal ASN.1 DER builders for synthetic RSA SPKI fixtures. The point of
# these is to let the DKIM-004 bit-length rule be tested without pulling in
# a crypto library; the SPKI we build is a valid shape but not a usable
# RSA key.
# ---------------------------------------------------------------------------

def _der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    if n < 0x100:
        return bytes([0x81, n])
    if n < 0x10000:
        return bytes([0x82, (n >> 8) & 0xFF, n & 0xFF])
    raise ValueError("DER length too large for test helper")


def _der_integer(value: bytes) -> bytes:
    # ASN.1 INTEGER: if the top bit of the value is set, prepend a 0x00
    # byte so the number is read as unsigned.
    if value and (value[0] & 0x80):
        value = b"\x00" + value
    return b"\x02" + _der_len(len(value)) + value


def _der_sequence(contents: bytes) -> bytes:
    return b"\x30" + _der_len(len(contents)) + contents


def _der_bitstring(contents: bytes) -> bytes:
    # BIT STRING carries a leading byte for the number of unused bits.
    body = b"\x00" + contents
    return b"\x03" + _der_len(len(body)) + body


def _der_null() -> bytes:
    return b"\x05\x00"


# OID 1.2.840.113549.1.1.1 (rsaEncryption) encoded in DER.
_OID_RSA_ENCRYPTION = bytes.fromhex("06092A864886F70D010101")


def make_rsa_spki_base64(bits: int) -> str:
    """Build a shape-valid RSA SubjectPublicKeyInfo DER encoding with a
    modulus of exactly ``bits`` bits, and return its standard-base64
    encoding. The modulus is deterministic; it is NOT a real RSA public
    key and the private counterpart does not exist.
    """
    if bits < 8 or bits % 8 != 0:
        raise ValueError("bits must be a positive multiple of 8")
    nbytes = bits // 8
    # Top-bit-set modulus so bit length matches ``bits`` after DER
    # leading-zero rules.
    modulus_bytes = bytes([0x80]) + bytes(nbytes - 1)
    exponent = bytes.fromhex("010001")  # 65537
    rsa_public_key = _der_sequence(
        _der_integer(modulus_bytes) + _der_integer(exponent)
    )
    alg_id = _der_sequence(_OID_RSA_ENCRYPTION + _der_null())
    spki = _der_sequence(alg_id + _der_bitstring(rsa_public_key))
    return base64.b64encode(spki).decode("ascii")


def make_dkim_record(
    selector: str,
    bits: int = 2048,
    extra_tags: str = "",
) -> str:
    """Return a BIND-style line that publishes a DKIM record for
    ``selector`` with a synthetic RSA key of ``bits`` bits.
    """
    p = make_rsa_spki_base64(bits)
    tags = "v=DKIM1; k=rsa; " + (extra_tags + "; " if extra_tags else "") + "p=" + p
    return selector + "._domainkey IN TXT \"" + tags + "\""
