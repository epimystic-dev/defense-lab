"""composecheck - static linter for Dockerfile and docker-compose files.

Reads a Dockerfile and / or a docker-compose.yml the developer has
saved and reports posture defects against public container-security
guidance (CIS Docker Benchmark, NIST SP 800-190, OWASP Docker Top 10,
MITRE CWE).

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
