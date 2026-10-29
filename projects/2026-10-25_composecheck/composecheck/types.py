"""Shared datatypes for composecheck.

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


class FileKind(str, Enum):
    DOCKERFILE = "dockerfile"
    COMPOSE = "compose"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class Finding:
    """One rule firing against one Dockerfile instruction or one compose
    service property at one line.
    """

    rule_id: str
    severity: Severity
    message: str
    subject: str          # instruction keyword / service name / "<file>"
    line: int
    path: str = ""
    hint: str = ""
    citation: str = ""

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "message": self.message,
            "subject": self.subject,
            "line": self.line,
            "path": self.path,
            "hint": self.hint,
            "citation": self.citation,
        }


@dataclass
class ScanResult:
    """The outcome of scanning one or more input files."""

    findings: List[Finding] = field(default_factory=list)
    files_scanned: int = 0
    instructions_scanned: int = 0
    verdict: Verdict = Verdict.UNKNOWN
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "verdict": self.verdict.value,
            "files_scanned": self.files_scanned,
            "instructions_scanned": self.instructions_scanned,
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

    def rule_enabled(self, rule_id: str) -> bool:
        if self.only and rule_id not in self.only:
            return False
        if rule_id in self.disabled:
            return False
        return True


__all__ = [
    "Severity",
    "Verdict",
    "FileKind",
    "Finding",
    "ScanResult",
    "Options",
]
