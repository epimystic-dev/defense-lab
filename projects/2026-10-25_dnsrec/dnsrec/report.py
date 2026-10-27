"""Text and JSON output formatting for dnsrec."""

from __future__ import annotations

import json
from typing import TextIO

from .types import ScanResult, Severity


_SEVERITY_ORDER = (Severity.HIGH, Severity.MEDIUM, Severity.INFO)


def _severity_label(sev: Severity) -> str:
    return sev.value


def _visible(text: str) -> str:
    """Render ``text`` so every character is printable ASCII.

    Any character outside printable ASCII is written as ``<U+XXXX>``.
    This has two purposes, each from a hard-won lesson in the sibling
    labs:

    * A report must never crash on a console that cannot encode what
      it is reporting. A Windows console on code page 1252 cannot
      encode a non-Latin-1 character, and echoing one raw crashes the
      reporter mid-write (traceback, no finding).
    * Email-authentication records occasionally carry homograph owners
      or zero-width characters pasted from a chat client; a report that
      re-echoed those raw would reconceal them in the output meant to
      expose them.
    """
    out = []
    for ch in text:
        cp = ord(ch)
        if 32 <= cp < 127:
            out.append(ch)
        else:
            out.append("<U+%04X>" % cp)
    return "".join(out)


def write_text(result: ScanResult, stream: TextIO) -> None:
    """Emit a human-readable report. Each finding occupies up to three
    lines (header, hint, citation) so grep-based CI pipelines can anchor
    on the rule-id line.
    """
    if not result.findings:
        stream.write(
            "dnsrec: " + result.verdict.value
            + "; files=" + str(result.files_scanned)
            + " records=" + str(result.records_scanned)
            + " findings=0\n"
        )
        return
    by_sev = {s: [f for f in result.findings if f.severity is s]
              for s in _SEVERITY_ORDER}
    for sev in _SEVERITY_ORDER:
        for f in by_sev[sev]:
            location = _visible(f.path)
            if f.line:
                location += ":" + str(f.line)
            owner = f.owner or "(no owner)"
            stream.write(
                _severity_label(sev) + " " + f.rule_id
                + " " + location
                + " [" + _visible(owner) + "]: "
                + _visible(f.message) + "\n"
            )
            if f.hint:
                stream.write("    hint: " + _visible(f.hint) + "\n")
            if f.citation:
                stream.write("    cite: " + _visible(f.citation) + "\n")
    stream.write(
        "dnsrec: " + result.verdict.value
        + "; files=" + str(result.files_scanned)
        + " records=" + str(result.records_scanned)
        + " findings=" + str(len(result.findings)) + "\n"
    )


def write_json(result: ScanResult, stream: TextIO) -> None:
    json.dump(result.to_dict(), stream, indent=2)
    stream.write("\n")


__all__ = ["write_text", "write_json"]
