"""headerscheck - static linter for saved HTTP response headers.

Reads a response the operator captured (raw HTTP, headers-only, HAR
entry, or a small headers-JSON blob) and reports security-header
posture defects against the OWASP Secure Headers Project baseline,
the OWASP Application Security Verification Standard (ASVS v4) web
protections section, and the IETF cookie and HSTS specifications.

Zero dependencies. Python 3.9+.
"""

from __future__ import annotations

__version__ = "0.1.0"

from .rules import REGISTRY, Check, Rule
from .types import Finding, Options, ScanResult, Severity, Verdict

ALL_RULES = REGISTRY

__all__ = [
    "__version__",
    "Severity",
    "Verdict",
    "Finding",
    "ScanResult",
    "Options",
    "ALL_RULES",
    "Rule",
    "REGISTRY",
    "Check",
]
