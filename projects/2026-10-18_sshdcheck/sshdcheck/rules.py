"""Rule registry for sshdcheck.

Fifteen hardening-posture rules on the sshd_config directive surface,
each citing the public control it implements. Rule IDs use the ``SSH-``
prefix; the lab-wide shared surface exposes this list as ``ALL_RULES``.

Rules are grounded in three public sources:

  * CIS Benchmark for Linux Distributions, section 5.2 (SSH Server
    Configuration), 2026 revision - the per-directive hardening
    settings every rule here is anchored on.
  * Mozilla OpenSSH Guidelines (infosec.mozilla.org/guidelines/openssh)
    - the modern-cipher / modern-MAC / modern-KEX allowlists SSH-011,
    SSH-012, SSH-013 enforce.
  * NIST SP 800-53 revision 5 - AC-17 (Remote Access), IA-2 (Identifier
    and Authentication), SC-8 (Transmission Confidentiality).

The rules capture SHAPE defects visible in the operator's saved file;
they do not test a live sshd server. A clean run is origin-valid, not
verified-safe.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Set

from .parse import (
    Directive,
    effective_global,
    index_by_keyword,
    split_csv_or_space,
    value_truthy,
)
from .types import Finding, Options, Severity


# A check receives the index of global directives (keyword ->
# ordered list), the raw text (unused by most rules but passed for
# future rules), the path label, options, and the context dict (for
# tools that need to share state across rules). It returns zero or
# more Findings.
Check = Callable[
    [Dict[str, List[Directive]], str, str, Options, dict],
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
# Mozilla OpenSSH Guidelines "modern" allowlists (operator-saved file is
# evaluated against this; a value NOT in the allowlist is a finding).
# These are the string values the sshd_config documents - no scraping,
# no live lookups.
# ---------------------------------------------------------------------------

MODERN_CIPHERS = {
    "chacha20-poly1305@openssh.com",
    "aes256-gcm@openssh.com",
    "aes128-gcm@openssh.com",
    "aes256-ctr",
    "aes192-ctr",
    "aes128-ctr",
}

MODERN_MACS = {
    "hmac-sha2-512-etm@openssh.com",
    "hmac-sha2-256-etm@openssh.com",
    "umac-128-etm@openssh.com",
    "hmac-sha2-512",
    "hmac-sha2-256",
    "umac-128@openssh.com",
}

MODERN_KEX = {
    "sntrup761x25519-sha512@openssh.com",
    "curve25519-sha256",
    "curve25519-sha256@libssh.org",
    "diffie-hellman-group16-sha512",
    "diffie-hellman-group18-sha512",
    "diffie-hellman-group-exchange-sha256",
    "diffie-hellman-group14-sha256",
    "mlkem768x25519-sha256",
}


# ---------------------------------------------------------------------------
# Rule check implementations.
# ---------------------------------------------------------------------------

def _mk(
    rule_id: str,
    severity: Severity,
    message: str,
    directive: str,
    line: int,
    path: str,
    hint: str,
    citation: str,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=severity,
        message=message,
        directive=directive,
        line=line,
        path=path,
        hint=hint,
        citation=citation,
    )


def _check_permit_root_login(index, path, content, options, context):
    d = effective_global(index, "PermitRootLogin")
    citation = "CIS 5.2.7; NIST SP 800-53 AC-6(2)"
    if d is None:
        # OpenSSH's compiled default has drifted across versions; a
        # saved file that omits it is a HIGH finding because the
        # posture is unspecified in the operator's own artifact.
        return [_mk(
            "SSH-001", Severity.HIGH,
            "PermitRootLogin is not set; the saved file does not pin"
            " a posture",
            "PermitRootLogin", 0, path,
            "set PermitRootLogin no, or 'prohibit-password' only if"
            " key-only root login is a documented requirement",
            citation,
        )]
    v = d.value.strip().lower()
    if v == "yes":
        return [_mk(
            "SSH-001", Severity.HIGH,
            "PermitRootLogin is yes",
            "PermitRootLogin", d.line, path,
            "set PermitRootLogin no; require login as a regular user"
            " followed by sudo",
            citation,
        )]
    if v in ("without-password", "prohibit-password"):
        return [_mk(
            "SSH-001", Severity.MEDIUM,
            "PermitRootLogin is " + v + "; direct root login remains"
            " enabled, keyed-only",
            "PermitRootLogin", d.line, path,
            "set PermitRootLogin no unless key-only root login is a"
            " documented requirement",
            citation,
        )]
    if v == "forced-commands-only":
        return []
    if v == "no":
        return []
    return [_mk(
        "SSH-001", Severity.MEDIUM,
        "PermitRootLogin has an unrecognised value: " + d.value,
        "PermitRootLogin", d.line, path,
        "accepted values are yes / no / prohibit-password /"
        " forced-commands-only",
        citation,
    )]


def _check_password_authentication(index, path, content, options, context):
    d = effective_global(index, "PasswordAuthentication")
    citation = (
        "CIS 5.2.9; NIST SP 800-63B 5.1.1.2 (memorized-secret"
        " authenticator over the network)"
    )
    if d is None:
        # OpenSSH defaults to yes; a saved file that omits it inherits
        # the weak default.
        return [_mk(
            "SSH-002", Severity.HIGH,
            "PasswordAuthentication is not set; the OpenSSH default is"
            " yes",
            "PasswordAuthentication", 0, path,
            "set PasswordAuthentication no and rely on PubkeyAuthentication",
            citation,
        )]
    v = value_truthy(d.value)
    if v is True:
        return [_mk(
            "SSH-002", Severity.HIGH,
            "PasswordAuthentication is yes",
            "PasswordAuthentication", d.line, path,
            "set PasswordAuthentication no and rely on PubkeyAuthentication;"
            " passwords over SSH are the primary brute-force surface",
            citation,
        )]
    if v is False:
        return []
    return [_mk(
        "SSH-002", Severity.MEDIUM,
        "PasswordAuthentication has an unrecognised value: " + d.value,
        "PasswordAuthentication", d.line, path,
        "set PasswordAuthentication no", citation,
    )]


def _check_permit_empty_passwords(index, path, content, options, context):
    d = effective_global(index, "PermitEmptyPasswords")
    citation = "CIS 5.2.11; NIST SP 800-53 IA-5"
    if d is None:
        # Default is no; absent is fine but we still note at INFO under strict.
        return []
    v = value_truthy(d.value)
    if v is True:
        return [_mk(
            "SSH-003", Severity.HIGH,
            "PermitEmptyPasswords is yes",
            "PermitEmptyPasswords", d.line, path,
            "set PermitEmptyPasswords no", citation,
        )]
    return []


def _check_protocol(index, path, content, options, context):
    d = effective_global(index, "Protocol")
    citation = "CIS 5.2.1; CWE-327; SSH protocol 1 is cryptographically broken"
    if d is None:
        return []
    tokens = {t.strip() for t in d.value.replace(",", " ").split()}
    if "1" in tokens:
        return [_mk(
            "SSH-004", Severity.HIGH,
            "Protocol declares SSH protocol 1 (" + d.value + ")",
            "Protocol", d.line, path,
            "remove '1' and leave only '2'; SSH 1 is cryptographically"
            " broken and no modern sshd honours it",
            citation,
        )]
    return []


def _check_x11_forwarding(index, path, content, options, context):
    d = effective_global(index, "X11Forwarding")
    citation = "CIS 5.2.4"
    if d is None:
        return []
    v = value_truthy(d.value)
    if v is True:
        return [_mk(
            "SSH-005", Severity.MEDIUM,
            "X11Forwarding is yes",
            "X11Forwarding", d.line, path,
            "set X11Forwarding no unless the host explicitly exports X;"
            " a compromised client can hijack keystrokes through the"
            " forwarded display",
            citation,
        )]
    return []


def _check_max_auth_tries(index, path, content, options, context):
    d = effective_global(index, "MaxAuthTries")
    citation = "CIS 5.2.5; NIST SP 800-53 AC-7"
    if d is None:
        return [_mk(
            "SSH-006", Severity.MEDIUM,
            "MaxAuthTries is not set; the OpenSSH default is 6",
            "MaxAuthTries", 0, path,
            "set MaxAuthTries to 4 or less", citation,
        )]
    try:
        n = int(d.value.split()[0])
    except (ValueError, IndexError):
        return [_mk(
            "SSH-006", Severity.MEDIUM,
            "MaxAuthTries value is not an integer: " + d.value,
            "MaxAuthTries", d.line, path,
            "set MaxAuthTries to 4 or less", citation,
        )]
    if n > 4:
        return [_mk(
            "SSH-006", Severity.MEDIUM,
            "MaxAuthTries is " + str(n) + " (threshold 4)",
            "MaxAuthTries", d.line, path,
            "lower MaxAuthTries to 4 or less to shrink the brute-force"
            " surface per TCP connection",
            citation,
        )]
    return []


def _check_login_grace_time(index, path, content, options, context):
    d = effective_global(index, "LoginGraceTime")
    citation = "CIS 5.2.17"
    if d is None:
        return [_mk(
            "SSH-007", Severity.MEDIUM,
            "LoginGraceTime is not set; the OpenSSH default is 120s",
            "LoginGraceTime", 0, path,
            "set LoginGraceTime 60 or lower", citation,
        )]
    seconds = _parse_time_spec(d.value)
    if seconds is None:
        return [_mk(
            "SSH-007", Severity.MEDIUM,
            "LoginGraceTime value is not a parseable duration: " + d.value,
            "LoginGraceTime", d.line, path,
            "set LoginGraceTime 60", citation,
        )]
    if seconds == 0:
        return [_mk(
            "SSH-007", Severity.HIGH,
            "LoginGraceTime is 0 (unlimited); unauthenticated connections"
            " can hold file descriptors indefinitely",
            "LoginGraceTime", d.line, path,
            "set LoginGraceTime 60", citation,
        )]
    if seconds > 60:
        return [_mk(
            "SSH-007", Severity.MEDIUM,
            "LoginGraceTime is " + str(seconds) + "s (threshold 60s)",
            "LoginGraceTime", d.line, path,
            "lower LoginGraceTime to 60 or less", citation,
        )]
    return []


def _check_client_alive(index, path, content, options, context):
    """ClientAliveInterval must be > 0 and ClientAliveCountMax <= 3."""
    citation = "CIS 5.2.18 / 5.2.19"
    interval = effective_global(index, "ClientAliveInterval")
    count = effective_global(index, "ClientAliveCountMax")
    out: List[Finding] = []
    interval_seconds: Optional[int] = None
    if interval is None:
        out.append(_mk(
            "SSH-008", Severity.MEDIUM,
            "ClientAliveInterval is not set; idle sessions can persist"
            " indefinitely",
            "ClientAliveInterval", 0, path,
            "set ClientAliveInterval 300 (5 minutes)", citation,
        ))
    else:
        interval_seconds = _parse_time_spec(interval.value)
        if interval_seconds is None:
            # Unparseable duration: the operator's intent is undefined,
            # so the posture is not pinned. Parity with SSH-006 and
            # SSH-007, which flag unparseable values on their own
            # keywords.
            out.append(_mk(
                "SSH-008", Severity.MEDIUM,
                "ClientAliveInterval value is not a parseable duration: "
                + interval.value,
                "ClientAliveInterval", interval.line, path,
                "set ClientAliveInterval 300 (5 minutes)", citation,
            ))
        elif interval_seconds == 0:
            out.append(_mk(
                "SSH-008", Severity.MEDIUM,
                "ClientAliveInterval is 0; idle sessions can persist"
                " indefinitely",
                "ClientAliveInterval", interval.line, path,
                "set ClientAliveInterval 300 (5 minutes)", citation,
            ))
    if count is not None:
        try:
            cmax = int(count.value.split()[0])
        except (ValueError, IndexError):
            cmax = None
        if cmax is None:
            # Unparseable integer: parity with the SSH-006 branch that
            # flags a non-integer MaxAuthTries value.
            out.append(_mk(
                "SSH-008", Severity.MEDIUM,
                "ClientAliveCountMax value is not an integer: "
                + count.value,
                "ClientAliveCountMax", count.line, path,
                "set ClientAliveCountMax to 3 or less", citation,
            ))
        elif cmax > 3:
            out.append(_mk(
                "SSH-008", Severity.MEDIUM,
                "ClientAliveCountMax is " + str(cmax) + " (threshold 3)",
                "ClientAliveCountMax", count.line, path,
                "lower ClientAliveCountMax to 3 or less", citation,
            ))
    return out


def _check_hostbased(index, path, content, options, context):
    d = effective_global(index, "HostbasedAuthentication")
    citation = "CIS 5.2.8; NIST SP 800-53 IA-2"
    if d is None:
        return []
    if value_truthy(d.value) is True:
        return [_mk(
            "SSH-009", Severity.HIGH,
            "HostbasedAuthentication is yes",
            "HostbasedAuthentication", d.line, path,
            "set HostbasedAuthentication no; host-based trust transfers"
            " authentication to the client host and is a lateral-movement"
            " enabler",
            citation,
        )]
    return []


def _check_ignore_rhosts(index, path, content, options, context):
    d = effective_global(index, "IgnoreRhosts")
    citation = "CIS 5.2.7"
    if d is None:
        return [_mk(
            "SSH-010", Severity.MEDIUM,
            "IgnoreRhosts is not set; the posture is unspecified",
            "IgnoreRhosts", 0, path,
            "set IgnoreRhosts yes", citation,
        )]
    v = value_truthy(d.value)
    if v is False:
        return [_mk(
            "SSH-010", Severity.MEDIUM,
            "IgnoreRhosts is no; .rhosts and .shosts files are honoured",
            "IgnoreRhosts", d.line, path,
            "set IgnoreRhosts yes", citation,
        )]
    return []


def _check_ciphers(index, path, content, options, context):
    """Flag any cipher that is NOT in the Mozilla modern allowlist."""
    return _check_algo_allowlist(
        index, path,
        keyword="Ciphers",
        rule_id="SSH-011",
        allowlist=MODERN_CIPHERS,
        citation=(
            "Mozilla OpenSSH Guidelines (modern cipher set); CWE-327"
        ),
        hint=(
            "replace with the Mozilla modern cipher set:"
            " chacha20-poly1305@openssh.com, aes256-gcm@openssh.com,"
            " aes128-gcm@openssh.com, aes256-ctr, aes192-ctr, aes128-ctr"
        ),
    )


def _check_macs(index, path, content, options, context):
    return _check_algo_allowlist(
        index, path,
        keyword="MACs",
        rule_id="SSH-012",
        allowlist=MODERN_MACS,
        citation=(
            "Mozilla OpenSSH Guidelines (modern MAC set); CWE-327;"
            " non-ETM constructions and md5 / sha1-96 / umac-64 are"
            " cryptographically weak"
        ),
        hint=(
            "replace with the Mozilla modern MAC set:"
            " hmac-sha2-512-etm@openssh.com,"
            " hmac-sha2-256-etm@openssh.com, umac-128-etm@openssh.com"
        ),
    )


def _check_kex(index, path, content, options, context):
    return _check_algo_allowlist(
        index, path,
        keyword="KexAlgorithms",
        rule_id="SSH-013",
        allowlist=MODERN_KEX,
        citation=(
            "Mozilla OpenSSH Guidelines (modern KEX set); CWE-327;"
            " SHA-1-based KEX methods (group1-sha1, group14-sha1,"
            " group-exchange-sha1) are deprecated"
        ),
        hint=(
            "replace with the Mozilla modern KEX set:"
            " sntrup761x25519-sha512@openssh.com,"
            " curve25519-sha256, curve25519-sha256@libssh.org,"
            " diffie-hellman-group16-sha512,"
            " diffie-hellman-group18-sha512,"
            " diffie-hellman-group-exchange-sha256"
        ),
    )


def _check_algo_allowlist(
    index: Dict[str, List[Directive]],
    path: str,
    keyword: str,
    rule_id: str,
    allowlist: Set[str],
    citation: str,
    hint: str,
) -> List[Finding]:
    d = effective_global(index, keyword)
    if d is None:
        return []
    # The '+' / '-' / '^' value prefixes modify the compile-time default:
    # +X appends, -X removes, ^X promotes. The operator who set + or ^
    # is still responsible for the whole posture; we flag the file as
    # unpinned at INFO.
    val = d.value.strip()
    if val.startswith(("+", "-", "^")):
        return [Finding(
            rule_id=rule_id,
            severity=Severity.INFO,
            message=(
                keyword + " uses a prefix modifier (" + val[0]
                + "); the effective posture depends on the compile-time"
                " default and is not pinned in this file"
            ),
            directive=keyword,
            line=d.line,
            path=path,
            hint=(
                "pin the full algorithm list explicitly to make the"
                " posture visible in the file"
            ),
            citation=citation,
        )]
    tokens = split_csv_or_space(val)
    bad = [t for t in tokens if t not in allowlist]
    if not bad:
        return []
    return [Finding(
        rule_id=rule_id,
        severity=Severity.HIGH,
        message=(
            keyword + " includes value(s) outside the Mozilla modern"
            " allowlist: " + ", ".join(bad)
        ),
        directive=keyword,
        line=d.line,
        path=path,
        hint=hint,
        citation=citation,
    )]


def _check_log_level(index, path, content, options, context):
    d = effective_global(index, "LogLevel")
    citation = "CIS 5.2.3; NIST SP 800-53 AU-2"
    if d is None:
        return []
    v = d.value.strip().upper()
    weak = {"QUIET", "FATAL", "ERROR"}
    if v in weak:
        return [_mk(
            "SSH-014", Severity.INFO,
            "LogLevel is " + v + "; authentication events may not be"
            " recorded",
            "LogLevel", d.line, path,
            "set LogLevel INFO (or VERBOSE if key-fingerprint logging is"
            " a documented requirement)",
            citation,
        )]
    return []


def _check_use_pam(index, path, content, options, context):
    d = effective_global(index, "UsePAM")
    citation = "CIS 5.2.14; NIST SP 800-53 AC-7"
    if d is None:
        return []
    if value_truthy(d.value) is False:
        return [_mk(
            "SSH-015", Severity.MEDIUM,
            "UsePAM is no; PAM-mediated controls (account lockout,"
            " session recording) are bypassed",
            "UsePAM", d.line, path,
            "set UsePAM yes unless there is a documented reason to"
            " bypass PAM",
            citation,
        )]
    return []


# ---------------------------------------------------------------------------
# Small helpers used above.
# ---------------------------------------------------------------------------

def _parse_time_spec(value: str) -> Optional[int]:
    """Parse an sshd_config time duration into seconds.

    sshd_config documents a duration spec: an integer suffixed by one
    of s / m / h / d / w, or a bare integer (seconds). Values can be
    concatenated (e.g. '1h30m'). Return None on parse failure.
    """
    value = value.strip()
    if not value:
        return None
    total = 0
    i = 0
    saw_any = False
    while i < len(value):
        j = i
        while j < len(value) and value[j].isdigit():
            j += 1
        if j == i:
            return None
        n = int(value[i:j])
        unit = ""
        if j < len(value) and value[j].isalpha():
            unit = value[j].lower()
            j += 1
        multiplier = {
            "": 1, "s": 1, "m": 60, "h": 3600,
            "d": 86400, "w": 604800,
        }.get(unit)
        if multiplier is None:
            return None
        total += n * multiplier
        saw_any = True
        i = j
    return total if saw_any else None


# ---------------------------------------------------------------------------
# The registry. Order matters: the shared contract tests assert the
# first rule is SSH-001.
# ---------------------------------------------------------------------------

REGISTRY: List[Rule] = [
    Rule(
        id="SSH-001",
        severity=Severity.HIGH,
        title="PermitRootLogin is yes (or unspecified)",
        description=(
            "Direct root SSH login is the single most-attacked remote"
            " surface on Linux; the saved file must pin the posture."
        ),
        citation="CIS 5.2.7; NIST SP 800-53 AC-6(2)",
        check=_check_permit_root_login,
    ),
    Rule(
        id="SSH-002",
        severity=Severity.HIGH,
        title="PasswordAuthentication is yes (or unspecified)",
        description=(
            "Passwords over SSH are the primary brute-force target on"
            " internet-facing servers; key-only authentication closes"
            " it."
        ),
        citation="CIS 5.2.9; NIST SP 800-63B",
        check=_check_password_authentication,
    ),
    Rule(
        id="SSH-003",
        severity=Severity.HIGH,
        title="PermitEmptyPasswords is yes",
        description=(
            "Empty-password accounts can be reached from the network;"
            " empty passwords are categorically forbidden."
        ),
        citation="CIS 5.2.11",
        check=_check_permit_empty_passwords,
    ),
    Rule(
        id="SSH-004",
        severity=Severity.HIGH,
        title="Protocol declares SSH protocol 1",
        description=(
            "SSH protocol 1 is cryptographically broken; a saved file"
            " that declares it is a hard misconfiguration."
        ),
        citation="CIS 5.2.1; CWE-327",
        check=_check_protocol,
    ),
    Rule(
        id="SSH-005",
        severity=Severity.MEDIUM,
        title="X11Forwarding is yes",
        description=(
            "A compromised client can hijack keystrokes and screen"
            " content through the forwarded display."
        ),
        citation="CIS 5.2.4",
        check=_check_x11_forwarding,
    ),
    Rule(
        id="SSH-006",
        severity=Severity.MEDIUM,
        title="MaxAuthTries exceeds 4",
        description=(
            "Each additional attempt enlarges the brute-force surface"
            " per TCP connection; CIS requires <=4."
        ),
        citation="CIS 5.2.5",
        check=_check_max_auth_tries,
    ),
    Rule(
        id="SSH-007",
        severity=Severity.MEDIUM,
        title="LoginGraceTime exceeds 60s (or is unlimited)",
        description=(
            "Longer grace times let unauthenticated connections hold"
            " file descriptors, enabling a slow-exhaustion DoS surface."
        ),
        citation="CIS 5.2.17",
        check=_check_login_grace_time,
    ),
    Rule(
        id="SSH-008",
        severity=Severity.MEDIUM,
        title="ClientAlive settings leave idle sessions open",
        description=(
            "ClientAliveInterval 0 or missing, and ClientAliveCountMax"
            " > 3, leave orphaned sessions reachable indefinitely."
        ),
        citation="CIS 5.2.18 / 5.2.19",
        check=_check_client_alive,
    ),
    Rule(
        id="SSH-009",
        severity=Severity.HIGH,
        title="HostbasedAuthentication is yes",
        description=(
            "Host-based trust transfers authentication to the client"
            " host and is a documented lateral-movement enabler."
        ),
        citation="CIS 5.2.8; NIST SP 800-53 IA-2",
        check=_check_hostbased,
    ),
    Rule(
        id="SSH-010",
        severity=Severity.MEDIUM,
        title="IgnoreRhosts is no (or unspecified)",
        description=(
            "Honouring .rhosts / .shosts widens the trust surface to"
            " every user's home directory."
        ),
        citation="CIS 5.2.7",
        check=_check_ignore_rhosts,
    ),
    Rule(
        id="SSH-011",
        severity=Severity.HIGH,
        title="Ciphers contains a value outside the modern allowlist",
        description=(
            "CBC-mode and 3DES / arcfour ciphers are cryptographically"
            " deprecated; Mozilla's modern allowlist is the public"
            " reference."
        ),
        citation="Mozilla OpenSSH Guidelines (modern cipher set)",
        check=_check_ciphers,
    ),
    Rule(
        id="SSH-012",
        severity=Severity.HIGH,
        title="MACs contains a value outside the modern allowlist",
        description=(
            "md5, sha1-96, umac-64, and non-ETM MAC constructions are"
            " cryptographically weak; Mozilla's modern MAC set is the"
            " public reference."
        ),
        citation="Mozilla OpenSSH Guidelines (modern MAC set); CWE-327",
        check=_check_macs,
    ),
    Rule(
        id="SSH-013",
        severity=Severity.HIGH,
        title="KexAlgorithms contains a value outside the modern allowlist",
        description=(
            "SHA-1-based KEX methods (group1-sha1, group14-sha1,"
            " group-exchange-sha1) are deprecated."
        ),
        citation="Mozilla OpenSSH Guidelines (modern KEX set); CWE-327",
        check=_check_kex,
    ),
    Rule(
        id="SSH-014",
        severity=Severity.INFO,
        title="LogLevel is below INFO",
        description=(
            "At QUIET / FATAL / ERROR, authentication events may not"
            " be recorded, breaking the audit trail."
        ),
        citation="CIS 5.2.3; NIST SP 800-53 AU-2",
        check=_check_log_level,
    ),
    Rule(
        id="SSH-015",
        severity=Severity.MEDIUM,
        title="UsePAM is no",
        description=(
            "Disabling PAM bypasses lockout, session recording, and"
            " account-expiry controls that live in PAM, not sshd."
        ),
        citation="CIS 5.2.14",
        check=_check_use_pam,
    ),
]


def run_all(
    directives: List[Directive],
    content: str,
    path: str,
    options: Options,
) -> List[Finding]:
    """Run every enabled rule once over the directive index."""
    index = index_by_keyword(directives)
    out: List[Finding] = []
    context: dict = {}
    for rule in REGISTRY:
        if not options.rule_enabled(rule.id):
            continue
        if rule.severity is Severity.INFO and not (
            options.strict or options.include_info
        ):
            continue
        out.extend(rule.check(index, path, content, options, context))
    out.sort(key=lambda f: (f.path, f.line, f.rule_id))
    return out


__all__ = ["Rule", "Check", "REGISTRY", "run_all"]
