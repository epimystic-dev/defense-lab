"""sshdcheck - static linter for sshd_config files.

Reads an OpenSSH ``sshd_config`` file the operator has saved and reports
posture defects against public hardening guidance (CIS Benchmark for
Linux Distributions, Mozilla OpenSSH Guidelines, NIST SP 800-53).

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
