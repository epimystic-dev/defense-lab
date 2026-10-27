"""Shared datatypes for dnsrec.

Severity, Verdict, Finding, ScanResult, and Options are the shape
surface the rest of the package - and the lab-wide shared contract -
agrees on.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Tuple


class Severity(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    INFO = "INFO"


class Verdict(str, Enum):
    HEALTHY = "healthy"
    NEEDS_ATTENTION = "needs-attention"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


class RecordKind(str, Enum):
    SPF = "spf"
    DMARC = "dmarc"
    DKIM = "dkim"
    OTHER = "other"


@dataclass(frozen=True)
class Record:
    """One parsed DNS record candidate from the input text."""

    owner: str            # left-hand name, canonicalised to lowercase, trailing dot stripped
    kind: RecordKind      # classified by owner / value shape
    value: str            # the TXT body with surrounding quotes stripped and continuations joined
    line: int             # 1-based line number of the record's first line in the source
    raw: str              # the full source line as read (newline stripped)


@dataclass(frozen=True)
class Finding:
    """One rule firing against one record at one line."""

    rule_id: str
    severity: Severity
    message: str
    owner: str
    line: int
    path: str = ""
    hint: str = ""
    citation: str = ""

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "message": self.message,
            "owner": self.owner,
            "line": self.line,
            "path": self.path,
            "hint": self.hint,
            "citation": self.citation,
        }


@dataclass
class ScanResult:
    """The outcome of scanning one or more DNS zone / record files."""

    findings: List[Finding] = field(default_factory=list)
    files_scanned: int = 0
    records_scanned: int = 0
    verdict: Verdict = Verdict.UNKNOWN
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "verdict": self.verdict.value,
            "files_scanned": self.files_scanned,
            "records_scanned": self.records_scanned,
            "findings": [f.to_dict() for f in self.findings],
            "error": self.error,
        }


@dataclass(frozen=True)
class Options:
    """Scan-time options surfaced by the CLI."""

    strict: bool = False
    include_info: bool = False
    disabled: Tuple[str, ...] = ()
    only: Tuple[str, ...] = ()
    # When set, every non-blank non-comment line is parsed as a bare
    # record value of the given kind, bypassing the BIND zone shape.
    # Useful for feeding the output of `dig +short TXT <name>`.
    force_kind: Optional[RecordKind] = None

    def rule_enabled(self, rule_id: str) -> bool:
        if self.only and rule_id not in self.only:
            return False
        if rule_id in self.disabled:
            return False
        return True


__all__ = [
    "Severity",
    "Verdict",
    "RecordKind",
    "Record",
    "Finding",
    "ScanResult",
    "Options",
]
