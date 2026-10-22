"""Text and JSON output formatting for headerscheck."""

from __future__ import annotations

import json
from typing import TextIO

from .types import ScanResult, Severity


_SEVERITY_ORDER = (Severity.HIGH, Severity.MEDIUM, Severity.INFO)


def _visible(text: str) -> str:
    """Render ``text`` so every character is printable ASCII; non-ASCII
    is rendered as <U+XXXX>. The reasoning is identical to sshdcheck's
    report: a Windows cp1252 console cannot encode non-Latin-1 content,
    and echoing it raw crashes the reporter. For a tool that may be
    reading response bodies full of surprises, this matters.
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
    if not result.findings:
        stream.write(
            "headerscheck: " + result.verdict.value
            + "; files=" + str(result.files_scanned)
            + " responses=" + str(result.responses_scanned)
            + " findings=0\n"
        )
        return
    by_sev = {s: [f for f in result.findings if f.severity is s]
              for s in _SEVERITY_ORDER}
    for sev in _SEVERITY_ORDER:
        for f in by_sev[sev]:
            header = f.header or "(none)"
            stream.write(
                sev.value + " " + f.rule_id
                + " " + _visible(f.path)
                + " [" + _visible(header) + "]: "
                + _visible(f.message) + "\n"
            )
            if f.hint:
                stream.write("    hint: " + _visible(f.hint) + "\n")
            if f.citation:
                stream.write("    cite: " + _visible(f.citation) + "\n")
    stream.write(
        "headerscheck: " + result.verdict.value
        + "; files=" + str(result.files_scanned)
        + " responses=" + str(result.responses_scanned)
        + " findings=" + str(len(result.findings)) + "\n"
    )


def write_json(result: ScanResult, stream: TextIO) -> None:
    json.dump(result.to_dict(), stream, indent=2)
    stream.write("\n")


__all__ = ["write_text", "write_json"]
