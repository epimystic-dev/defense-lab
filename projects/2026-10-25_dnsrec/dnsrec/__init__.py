"""dnsrec - static linter for SPF, DMARC, and DKIM DNS records.

Reads a BIND-style zone file (or one-record-per-line TXT export) the
operator has saved and reports posture defects against public email-
authentication guidance (IETF RFC 7208, RFC 7489, RFC 6376, RFC 8463,
NIST SP 800-177, and the M3AAWG Email Authentication Best Common
Practices).

Zero dependencies. Python 3.9+.
"""

from __future__ import annotations

__version__ = "0.1.0"

from .rules import REGISTRY, Check, Rule
from .types import Finding, Options, ScanResult, Severity, Verdict

# The lab's shared package surface (defense-lab/docs/CONVENTIONS.md)
# names the rule table ALL_RULES and the rule type Rule. The internal
# spelling stays REGISTRY / Check; ALL_RULES is a stable alias.
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
