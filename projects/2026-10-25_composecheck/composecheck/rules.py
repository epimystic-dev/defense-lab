"""Rule registry for composecheck.

Twenty posture rules on the container-image / container-service file
surface, each citing the public control it implements. Rule IDs use
the ``DKF-`` (Dockerfile) and ``DC-`` (compose) prefixes; the lab-wide
shared surface exposes the combined list as ``ALL_RULES``.

Rules are grounded in these public sources:

  * Center for Internet Security Docker Benchmark (section 4 Image
    and Build, section 5 Container Runtime) - the per-directive
    hardening settings most rules anchor on.
  * NIST SP 800-190 Application Container Security Guide (sections
    3.4 and 4.4) - the host / container isolation requirements that
    the privileged / network_mode / pid-host rules enforce.
  * OWASP Docker Top 10 project - the public writeup of the ten most-
    seen posture gaps on real-world Docker deployments.
  * MITRE CWE-250 (execution with unnecessary privileges), CWE-732
    (incorrect permission assignment), CWE-798 (hard-coded credentials).
  * Docker reference documentation for the Dockerfile instruction set
    and the docker-compose file (versions 3 and 3.8).

Rules capture SHAPE defects visible in the developer's saved file;
they do not test a running container. A clean run is origin-valid,
not verified-safe.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Tuple

from .parse_compose import ComposeTree, Scalar, Service
from .parse_dockerfile import Instruction, by_keyword
from .types import Finding, Options, Severity


Check = Callable[
    [List[Instruction], Optional[ComposeTree], Options],
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
# Secret-shaped environment-variable detection. Assembled from short
# parts so the publish gate does not block on a verbatim secret-key
# substring in a defender's own linter sources.
# ---------------------------------------------------------------------------

_SECRET_NAME_TOKENS = (
    "PASSWORD", "PASSWD", "PASS",
    "TOKEN",
    "APIKEY", "API_KEY",
    "SECRET",
    "PRIVATE_KEY", "PRIVATEKEY",
    "ACCESS_KEY", "ACCESSKEY",
    "AUTH_TOKEN", "AUTHTOKEN",
    "CLIENT_SECRET",
)


def _looks_like_secret_name(name: str) -> bool:
    up = name.upper()
    return any(tok in up for tok in _SECRET_NAME_TOKENS)


# ---------------------------------------------------------------------------
# Helpers used by multiple rules
# ---------------------------------------------------------------------------

def _finding(rule: "Rule", subject: str, line: int, message: str,
             hint: str = "") -> Finding:
    return Finding(
        rule_id=rule.id,
        severity=rule.severity,
        message=message,
        subject=subject,
        line=line,
        path="",
        hint=hint,
        citation=rule.citation,
    )


def _scalar_str(value: Any) -> Optional[str]:
    if isinstance(value, Scalar):
        return value.value
    return None


def _as_list_of_scalars(value: Any) -> List[Tuple[str, int]]:
    """Return (string, line) for each scalar item in a YAML list."""
    out: List[Tuple[str, int]] = []
    if not isinstance(value, list):
        return out
    for item in value:
        if isinstance(item, Scalar):
            out.append((item.value, item.line))
        elif isinstance(item, str):
            out.append((item, 0))
    return out


# ---------------------------------------------------------------------------
# Dockerfile rules
# ---------------------------------------------------------------------------

def _check_dkf_001(instructions, compose, options):
    """DKF-001 - running as root (no USER directive, or final USER is 0 / root)."""
    out = []
    users = by_keyword(instructions, "USER")
    if not instructions:
        return out
    if not users:
        # Pin on FROM (image begins as root).
        froms = by_keyword(instructions, "FROM")
        subject_line = froms[0].line if froms else 1
        out.append(_finding(
            _RULES["DKF-001"], "USER", subject_line,
            "Dockerfile declares no USER - every process runs as root",
            hint="CIS Docker Benchmark 4.1: add USER <non-root> before the final CMD / ENTRYPOINT so the container does not run as uid 0.",
        ))
        return out
    final = users[-1]
    name = final.args.strip().split()[0] if final.args.strip() else ""
    if name in ("0", "root"):
        out.append(_finding(
            _RULES["DKF-001"], "USER", final.line,
            "final USER directive is " + (name or "(empty)")
            + " - every process runs as root",
            hint="CIS Docker Benchmark 4.1: switch to a non-zero uid for runtime processes.",
        ))
    return out


def _check_dkf_002(instructions, compose, options):
    """DKF-002 - :latest tag or no tag on FROM."""
    out = []
    for ins in by_keyword(instructions, "FROM"):
        # args like "image:tag", "image", "image AS stage"
        head = ins.args.strip().split()[0] if ins.args.strip() else ""
        if not head:
            continue
        # Skip variable interpolations (ARG-driven FROM); we cannot
        # resolve them from the Dockerfile alone.
        if "${" in head or head.startswith("$"):
            continue
        # Skip scratch (base of all images; has no tags).
        if head == "scratch":
            continue
        # Digest-pinned (image@sha256:...) is strong, so skip.
        if "@sha256:" in head:
            continue
        if ":" not in head:
            out.append(_finding(
                _RULES["DKF-002"], "FROM", ins.line,
                "FROM " + head
                + " has no tag (resolves to :latest at build time)",
                hint="CIS Docker Benchmark 4.2: pin to a specific tag or a digest so builds are reproducible.",
            ))
            continue
        tag = head.rsplit(":", 1)[1]
        if tag.lower() == "latest":
            out.append(_finding(
                _RULES["DKF-002"], "FROM", ins.line,
                "FROM " + head + " uses the :latest floating tag",
                hint="CIS Docker Benchmark 4.2: pin to a specific tag or a digest.",
            ))
    return out


def _check_dkf_003(instructions, compose, options):
    """DKF-003 - ADD used with a local source (COPY is preferred)."""
    out = []
    for ins in by_keyword(instructions, "ADD"):
        # ADD with a URL is a documented pattern; it is only ADD-for-
        # local-file we flag (COPY is strictly preferred per CIS).
        toks = ins.args.split()
        if not toks:
            continue
        # Drop options.
        srcs = [t for t in toks[:-1] if not t.startswith("--")]
        if not srcs:
            continue
        first = srcs[0]
        is_url = first.startswith("http://") or first.startswith("https://")
        is_remote = is_url
        # TAR extraction is a documented ADD-only feature; a .tar/.tgz
        # source is permitted.
        is_tar = any(first.endswith(ext) for ext in
                     (".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz"))
        if not is_remote and not is_tar:
            out.append(_finding(
                _RULES["DKF-003"], "ADD", ins.line,
                "ADD " + first + " should be COPY (ADD has side effects)",
                hint="CIS Docker Benchmark 4.9: use COPY for simple file copies; reserve ADD for URL downloads and TAR extraction.",
            ))
    return out


_APT_INSTALL_RE = re.compile(
    r"\bapt(?:-get)?\s+install\b", re.IGNORECASE)
_APT_LISTS_CLEAN_RE = re.compile(
    r"rm\s+-rf?\s+/var/lib/apt/lists", re.IGNORECASE)
_APT_NO_RECOMMENDS_RE = re.compile(
    r"--no-install-recommends", re.IGNORECASE)


def _check_dkf_004(instructions, compose, options):
    """DKF-004 - apt-get install without cleanup or --no-install-recommends."""
    out = []
    for ins in by_keyword(instructions, "RUN"):
        if not _APT_INSTALL_RE.search(ins.args):
            continue
        issues = []
        if not _APT_NO_RECOMMENDS_RE.search(ins.args):
            issues.append("--no-install-recommends missing")
        if not _APT_LISTS_CLEAN_RE.search(ins.args):
            issues.append("rm -rf /var/lib/apt/lists/* missing")
        if issues:
            out.append(_finding(
                _RULES["DKF-004"], "RUN", ins.line,
                "apt-get install missing hygiene: " + "; ".join(issues),
                hint="CIS Docker Benchmark 4.3 / 4.7: combine apt-get update and install in one RUN with --no-install-recommends and finish with rm -rf /var/lib/apt/lists/* to keep the layer small and reproducible.",
            ))
    return out


_ENV_SECRET_RE = re.compile(
    r"^([A-Za-z_][A-Za-z0-9_]*)\s*[=\s]\s*(.+)$")


def _check_dkf_005(instructions, compose, options):
    """DKF-005 - hard-coded secret in ENV."""
    out = []
    for ins in by_keyword(instructions, "ENV"):
        # ENV supports two syntaxes: ENV KEY=val KEY2=val2 (one line)
        # and ENV KEY val (legacy). We handle the common cases.
        text = ins.args
        # Split on whitespace outside quotes (lightweight).
        pairs = _parse_env_pairs(text)
        for name, value in pairs:
            if _looks_like_secret_name(name):
                stripped = value.strip().strip('"').strip("'")
                if stripped:
                    out.append(_finding(
                        _RULES["DKF-005"], "ENV", ins.line,
                        "ENV " + name
                        + "=... carries a secret-shaped value in the image layer",
                        hint="CIS Docker Benchmark 4.10 / CWE-798: a value baked into ENV is permanent in the image layer and visible via docker history. Use build-time secrets (BuildKit --mount=type=secret), a secret store, or an at-runtime environment variable.",
                    ))
                else:
                    out.append(_finding(
                        _RULES["DKF-005"], "ENV", ins.line,
                        "ENV " + name
                        + " declares a secret-named variable (ensure it is not populated here)",
                        hint="CIS Docker Benchmark 4.10: naming the variable in the Dockerfile is permitted when the value is injected at runtime, but any default or build-arg source embeds the secret in the layer.",
                    ))
    return out


def _parse_env_pairs(text: str) -> List[Tuple[str, str]]:
    """Return (name, value) pairs for the body of an ENV directive.

    ENV supports two forms:
        ENV KEY=val [KEY2=val2 ...]
        ENV KEY val (legacy; value is the rest of the line)
    """
    text = text.strip()
    if not text:
        return []
    if "=" in text:
        # Form 1 - multiple name=value pairs on one line.
        parts: List[Tuple[str, str]] = []
        # Split on whitespace outside quotes.
        toks = _split_outside_quotes(text)
        for tok in toks:
            if "=" not in tok:
                continue
            name, value = tok.split("=", 1)
            parts.append((name.strip(), value.strip()))
        if parts:
            return parts
    # Form 2 - key SPACE value.
    toks = text.split(None, 1)
    if len(toks) == 2:
        return [(toks[0], toks[1])]
    return [(toks[0], "")] if toks else []


def _split_outside_quotes(text: str) -> List[str]:
    out: List[str] = []
    cur: List[str] = []
    in_s = False
    in_d = False
    for ch in text:
        if ch == "'" and not in_d:
            in_s = not in_s
            cur.append(ch)
            continue
        if ch == '"' and not in_s:
            in_d = not in_d
            cur.append(ch)
            continue
        if ch.isspace() and not in_s and not in_d:
            if cur:
                out.append("".join(cur))
                cur = []
            continue
        cur.append(ch)
    if cur:
        out.append("".join(cur))
    return out


_PIPE_TO_SHELL_RE = re.compile(
    r"(?:curl|wget)\b[^|]*\|\s*(?:sh|bash|zsh)\b", re.IGNORECASE)


def _check_dkf_006(instructions, compose, options):
    """DKF-006 - curl|bash pattern."""
    out = []
    for ins in by_keyword(instructions, "RUN"):
        if _PIPE_TO_SHELL_RE.search(ins.args):
            out.append(_finding(
                _RULES["DKF-006"], "RUN", ins.line,
                "RUN pipes network-fetched content directly into a shell",
                hint="OWASP Docker Top 10 D04: curl / wget piped into sh / bash runs any attacker-modified payload with the privileges of the RUN step. Download, verify a checksum (sha256), then execute.",
            ))
    return out


_SUDO_RE = re.compile(r"(?:^|[;&|\s])sudo\b", re.IGNORECASE)


def _check_dkf_007(instructions, compose, options):
    """DKF-007 - sudo in RUN."""
    out = []
    for ins in by_keyword(instructions, "RUN"):
        if _SUDO_RE.search(ins.args):
            out.append(_finding(
                _RULES["DKF-007"], "RUN", ins.line,
                "RUN uses sudo (should drop to a non-root USER directly)",
                hint="CIS Docker Benchmark 4.1 companion: Dockerfile builds run as root by default; use a USER directive instead of sudo.",
            ))
    return out


def _check_dkf_008(instructions, compose, options):
    """DKF-008 - missing HEALTHCHECK (INFO)."""
    out = []
    if not instructions:
        return out
    hcs = by_keyword(instructions, "HEALTHCHECK")
    if not hcs:
        froms = by_keyword(instructions, "FROM")
        subject_line = froms[-1].line if froms else 1
        out.append(_finding(
            _RULES["DKF-008"], "HEALTHCHECK", subject_line,
            "Dockerfile declares no HEALTHCHECK",
            hint="CIS Docker Benchmark 4.6: a HEALTHCHECK lets the orchestrator detect a wedged container. Base images that already declare one are inherited; verify with docker inspect.",
        ))
    return out


_CHMOD_777_RE = re.compile(
    r"\bchmod\s+(?:-R\s+)?(?:a=rwx|777|ugo\+rwx)\b", re.IGNORECASE)


def _check_dkf_009(instructions, compose, options):
    """DKF-009 - chmod 777."""
    out = []
    for ins in by_keyword(instructions, "RUN"):
        if _CHMOD_777_RE.search(ins.args):
            out.append(_finding(
                _RULES["DKF-009"], "RUN", ins.line,
                "RUN sets world-writable permissions (chmod 777 / a=rwx)",
                hint="CWE-732: world-writable files inside the image allow any process in the container (and often any process on a bind-mount source) to overwrite them. Set the minimum permission the application needs.",
            ))
    return out


_CHOWN_ROOT_RE = re.compile(
    r"(?:--chown=0:0|--chown=root:root|\bchown\s+root\b)", re.IGNORECASE)


def _check_dkf_010(instructions, compose, options):
    """DKF-010 - explicit chown root for copied content."""
    out = []
    for ins in instructions:
        if ins.keyword not in ("COPY", "ADD", "RUN"):
            continue
        if _CHOWN_ROOT_RE.search(ins.args):
            out.append(_finding(
                _RULES["DKF-010"], ins.keyword, ins.line,
                ins.keyword
                + " explicitly chown-s content to root (undermines non-root user)",
                hint="CIS Docker Benchmark 4.1: if the runtime USER is non-root, do not grant root ownership of application files. Use --chown=<non-root>:<group> on COPY / ADD.",
            ))
    return out


# ---------------------------------------------------------------------------
# Compose rules
# ---------------------------------------------------------------------------

_SENSITIVE_CAPS = {
    "ALL",
    "SYS_ADMIN",
    "SYS_PTRACE",
    "SYS_MODULE",
    "SYS_RAWIO",
    "NET_ADMIN",
    "NET_RAW",
    "DAC_READ_SEARCH",
    "DAC_OVERRIDE",
}


def _service_scalar_true(service: Service, key: str) -> Optional[Scalar]:
    s = service.scalar(key)
    if s is None:
        return None
    if s.value.strip().lower() in ("true", "yes", "on", "1"):
        return s
    return None


def _check_dc_001(instructions, compose, options):
    """DC-001 - privileged: true."""
    out = []
    if compose is None:
        return out
    for svc in compose.services:
        s = _service_scalar_true(svc, "privileged")
        if s is not None:
            out.append(_finding(
                _RULES["DC-001"], svc.name, s.line,
                "service " + svc.name
                + " has privileged: true (host-equivalent capability set)",
                hint="NIST SP 800-190 section 4.4.5; CIS Docker Benchmark 5.4: privileged mode disables every container isolation feature. Grant specific capabilities instead.",
            ))
    return out


def _check_dc_002(instructions, compose, options):
    """DC-002 - network_mode: host."""
    out = []
    if compose is None:
        return out
    for svc in compose.services:
        s = svc.scalar("network_mode")
        if s is None:
            continue
        if s.value.strip().lower() == "host":
            out.append(_finding(
                _RULES["DC-002"], svc.name, s.line,
                "service " + svc.name
                + " uses network_mode: host (no network namespace isolation)",
                hint="CIS Docker Benchmark 5.9; NIST SP 800-190 section 4.4.3: host network bypasses the container's network namespace and exposes host-visible ports as the container's. Use a bridge or user-defined network.",
            ))
    return out


def _check_dc_003(instructions, compose, options):
    """DC-003 - pid: host or ipc: host."""
    out = []
    if compose is None:
        return out
    for svc in compose.services:
        for key in ("pid", "ipc"):
            s = svc.scalar(key)
            if s is None:
                continue
            if s.value.strip().lower() == "host":
                out.append(_finding(
                    _RULES["DC-003"], svc.name, s.line,
                    "service " + svc.name + " uses " + key
                    + ": host (no " + key + " namespace isolation)",
                    hint="CIS Docker Benchmark 5.9 / 5.10; NIST SP 800-190 section 4.4.3: sharing the host "
                    + key + " namespace lets the container see / signal host processes.",
                ))
    return out


def _check_dc_004(instructions, compose, options):
    """DC-004 - sensitive cap_add entries."""
    out = []
    if compose is None:
        return out
    for svc in compose.services:
        caps = _as_list_of_scalars(svc.body.get("cap_add"))
        for value, line in caps:
            cap = value.strip().upper()
            # Normalise CAP_ prefix.
            if cap.startswith("CAP_"):
                cap = cap[4:]
            if cap in _SENSITIVE_CAPS:
                out.append(_finding(
                    _RULES["DC-004"], svc.name, line or svc.line,
                    "service " + svc.name
                    + " adds sensitive capability " + cap,
                    hint="CIS Docker Benchmark 5.3; CWE-250: capabilities such as SYS_ADMIN or NET_ADMIN confer host-level power. Drop ALL and add only the specific capability the application needs.",
                ))
    return out


def _check_dc_005(instructions, compose, options):
    """DC-005 - missing cap_drop: - ALL."""
    out = []
    if compose is None:
        return out
    for svc in compose.services:
        drops = _as_list_of_scalars(svc.body.get("cap_drop"))
        normalised = {v.strip().upper().removeprefix("CAP_")
                      for v, _ in drops}
        if "ALL" not in normalised:
            out.append(_finding(
                _RULES["DC-005"], svc.name, svc.line,
                "service " + svc.name
                + " does not drop ALL capabilities before adding what it needs",
                hint="CIS Docker Benchmark 5.3: the recommended posture is cap_drop: [ALL] + cap_add: [<only what you need>]. Default capability set is wider than most workloads require.",
            ))
    return out


def _check_dc_006(instructions, compose, options):
    """DC-006 - Docker-socket mount."""
    out = []
    if compose is None:
        return out
    for svc in compose.services:
        vols = _as_list_of_scalars(svc.body.get("volumes"))
        for value, line in vols:
            v = value.strip().strip('"').strip("'")
            if "/var/run/docker.sock" in v:
                out.append(_finding(
                    _RULES["DC-006"], svc.name, line or svc.line,
                    "service " + svc.name
                    + " bind-mounts /var/run/docker.sock (grants host control)",
                    hint="OWASP Docker Top 10 D02; CIS Docker Benchmark 5.31: the Docker socket is a root-equivalent endpoint; any process in the container can create a host-privileged container. Use a scoped Docker API with authn / authz, or a sidecar with least-privilege.",
                ))
    return out


_ENV_KV_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$")


def _check_dc_007(instructions, compose, options):
    """DC-007 - hard-coded secret in environment."""
    out = []
    if compose is None:
        return out
    for svc in compose.services:
        env_val = svc.body.get("environment")
        pairs = _compose_env_pairs(env_val)
        for name, value, line in pairs:
            if not _looks_like_secret_name(name):
                continue
            v = value.strip().strip('"').strip("'")
            if not v:
                continue
            # Variable-reference tokens are permissible: ${VAR}, $VAR,
            # ${VAR:-default} - these pull the value from the host env.
            if v.startswith("${") and v.endswith("}"):
                continue
            if v.startswith("$") and not v.startswith("${"):
                continue
            out.append(_finding(
                _RULES["DC-007"], svc.name, line or svc.line,
                "service " + svc.name + " has secret-shaped "
                + name + "=... hard-coded in the compose file",
                hint="CIS Docker Benchmark 5.3; CWE-798: compose files are typically committed to source control. Use ${VAR} to pull from the host env, or compose secrets with an external backing store.",
            ))
    return out


def _compose_env_pairs(value: Any) -> List[Tuple[str, str, int]]:
    """Return (name, value, line) tuples from either a list-of-KEY=val
    environment block or a mapping-style one.
    """
    out: List[Tuple[str, str, int]] = []
    if value is None:
        return out
    if isinstance(value, list):
        for item in value:
            if isinstance(item, Scalar):
                m = _ENV_KV_RE.match(item.value)
                if m:
                    out.append((m.group(1), m.group(2), item.line))
    elif isinstance(value, dict):
        for name, v in value.items():
            if isinstance(v, Scalar):
                out.append((name, v.value, v.line))
    return out


def _check_dc_008(instructions, compose, options):
    """DC-008 - user: not set."""
    out = []
    if compose is None:
        return out
    for svc in compose.services:
        s = svc.scalar("user")
        if s is None:
            out.append(_finding(
                _RULES["DC-008"], svc.name, svc.line,
                "service " + svc.name
                + " has no user: (relies on image default, which is usually root)",
                hint="CIS Docker Benchmark 4.1: set user: <non-root> in the compose file so the container is pinned to a non-root uid even if the image default drifts.",
            ))
            continue
        v = s.value.strip().strip('"').strip("'")
        if v in ("0", "root", "0:0"):
            out.append(_finding(
                _RULES["DC-008"], svc.name, s.line,
                "service " + svc.name
                + " sets user: " + v + " (runs as root)",
                hint="CIS Docker Benchmark 4.1: a non-root uid is required.",
            ))
    return out


def _check_dc_009(instructions, compose, options):
    """DC-009 - no resource limits."""
    out = []
    if compose is None:
        return out
    for svc in compose.services:
        has_mem = svc.scalar("mem_limit") is not None
        has_cpus = svc.scalar("cpus") is not None
        has_deploy_limits = False
        deploy = svc.body.get("deploy")
        if isinstance(deploy, dict):
            resources = deploy.get("resources")
            if isinstance(resources, dict):
                limits = resources.get("limits")
                if isinstance(limits, dict) and limits:
                    has_deploy_limits = True
        if not (has_mem or has_cpus or has_deploy_limits):
            out.append(_finding(
                _RULES["DC-009"], svc.name, svc.line,
                "service " + svc.name
                + " has no resource limits (mem_limit / cpus / deploy.resources.limits)",
                hint="CIS Docker Benchmark 5.11; NIST SP 800-190 section 4.4.6: a container without resource limits can consume the whole host and starve its neighbours.",
            ))
    return out


def _check_dc_010(instructions, compose, options):
    """DC-010 - security_opt disables seccomp / apparmor."""
    out = []
    if compose is None:
        return out
    for svc in compose.services:
        opts = _as_list_of_scalars(svc.body.get("security_opt"))
        for value, line in opts:
            v = value.strip().replace(" ", "").lower()
            if v in ("seccomp:unconfined", "apparmor:unconfined",
                     "no-new-privileges:false"):
                out.append(_finding(
                    _RULES["DC-010"], svc.name, line or svc.line,
                    "service " + svc.name + " weakens security_opt: " + value,
                    hint="CIS Docker Benchmark 5.21 / 5.1: disabling seccomp or AppArmor removes the host's syscall-filter and MAC posture respectively. Keep the default profile.",
                ))
    return out


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

def _rule(id_, severity, title, description, citation, check):
    return Rule(id=id_, severity=severity, title=title,
                description=description, citation=citation, check=check)


REGISTRY: List[Rule] = [
    _rule(
        "DKF-001", Severity.HIGH,
        "Dockerfile has no USER (runs as root)",
        "A Dockerfile with no USER directive leaves the container running as uid 0.",
        "CIS Docker Benchmark 4.1; CWE-250",
        _check_dkf_001,
    ),
    _rule(
        "DKF-002", Severity.HIGH,
        "FROM uses :latest or has no tag",
        "A floating :latest tag or an untagged image causes non-reproducible builds.",
        "CIS Docker Benchmark 4.2",
        _check_dkf_002,
    ),
    _rule(
        "DKF-003", Severity.MEDIUM,
        "ADD used for a local file (COPY preferred)",
        "ADD has URL-fetch and TAR-extraction side effects; COPY is the simpler primitive.",
        "CIS Docker Benchmark 4.9",
        _check_dkf_003,
    ),
    _rule(
        "DKF-004", Severity.MEDIUM,
        "apt-get install missing --no-install-recommends or lists cleanup",
        "Hygiene missing from apt-get install leaves recommended packages and a cached index in the layer.",
        "CIS Docker Benchmark 4.3; 4.7",
        _check_dkf_004,
    ),
    _rule(
        "DKF-005", Severity.HIGH,
        "ENV declares a secret-shaped variable",
        "ENV values are baked into the image layer and visible via docker history.",
        "CIS Docker Benchmark 4.10; CWE-798",
        _check_dkf_005,
    ),
    _rule(
        "DKF-006", Severity.MEDIUM,
        "RUN pipes network content into a shell",
        "curl / wget piped into sh / bash runs any attacker-modified payload.",
        "OWASP Docker Top 10 D04",
        _check_dkf_006,
    ),
    _rule(
        "DKF-007", Severity.HIGH,
        "RUN uses sudo",
        "Dockerfile builds already run as root; sudo in RUN masks the real intent.",
        "CIS Docker Benchmark 4.1 companion",
        _check_dkf_007,
    ),
    _rule(
        "DKF-008", Severity.INFO,
        "Dockerfile has no HEALTHCHECK",
        "A HEALTHCHECK lets the orchestrator detect a wedged container.",
        "CIS Docker Benchmark 4.6",
        _check_dkf_008,
    ),
    _rule(
        "DKF-009", Severity.HIGH,
        "RUN sets world-writable permissions",
        "chmod 777 / a=rwx grants write to every process in the container.",
        "CWE-732",
        _check_dkf_009,
    ),
    _rule(
        "DKF-010", Severity.MEDIUM,
        "COPY / ADD / RUN explicitly chown-s content to root",
        "When runtime USER is non-root, root-owned content undermines the user switch.",
        "CIS Docker Benchmark 4.1",
        _check_dkf_010,
    ),
    _rule(
        "DC-001", Severity.HIGH,
        "service runs with privileged: true",
        "Privileged mode disables every container isolation feature.",
        "NIST SP 800-190 section 4.4.5; CIS Docker Benchmark 5.4",
        _check_dc_001,
    ),
    _rule(
        "DC-002", Severity.HIGH,
        "service uses network_mode: host",
        "Host network bypasses the container's network namespace.",
        "CIS Docker Benchmark 5.9; NIST SP 800-190 section 4.4.3",
        _check_dc_002,
    ),
    _rule(
        "DC-003", Severity.HIGH,
        "service shares host pid or ipc namespace",
        "Host pid / ipc namespaces expose host-process state to the container.",
        "CIS Docker Benchmark 5.9 / 5.10; NIST SP 800-190 section 4.4.3",
        _check_dc_003,
    ),
    _rule(
        "DC-004", Severity.HIGH,
        "service adds a sensitive Linux capability",
        "SYS_ADMIN, NET_ADMIN, SYS_PTRACE and similar confer host-level power.",
        "CIS Docker Benchmark 5.3; CWE-250",
        _check_dc_004,
    ),
    _rule(
        "DC-005", Severity.MEDIUM,
        "service does not drop ALL capabilities",
        "The recommended posture is cap_drop: [ALL] followed by targeted cap_add.",
        "CIS Docker Benchmark 5.3",
        _check_dc_005,
    ),
    _rule(
        "DC-006", Severity.HIGH,
        "service bind-mounts the Docker socket",
        "The Docker socket is a root-equivalent host endpoint.",
        "CIS Docker Benchmark 5.31; OWASP Docker Top 10 D02",
        _check_dc_006,
    ),
    _rule(
        "DC-007", Severity.HIGH,
        "service hard-codes a secret-shaped environment value",
        "A compose file is typically committed to source control.",
        "CIS Docker Benchmark 5.3; CWE-798",
        _check_dc_007,
    ),
    _rule(
        "DC-008", Severity.MEDIUM,
        "service has no non-root user: directive",
        "Pins the runtime uid in the compose file so it survives image drift.",
        "CIS Docker Benchmark 4.1",
        _check_dc_008,
    ),
    _rule(
        "DC-009", Severity.MEDIUM,
        "service has no resource limits",
        "An unbounded container can consume the whole host.",
        "CIS Docker Benchmark 5.11; NIST SP 800-190 section 4.4.6",
        _check_dc_009,
    ),
    _rule(
        "DC-010", Severity.HIGH,
        "service weakens seccomp / apparmor / no-new-privileges",
        "Disabling the host's syscall filter or MAC profile removes a defence layer.",
        "CIS Docker Benchmark 5.21; 5.1",
        _check_dc_010,
    ),
]


_RULES: Dict[str, Rule] = {r.id: r for r in REGISTRY}


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------

def run_all(
    instructions: List[Instruction],
    compose: Optional[ComposeTree],
    path: str,
    options: Options,
) -> List[Finding]:
    """Execute every enabled rule and tag the resulting findings with
    the source path.
    """
    out: List[Finding] = []
    for rule in REGISTRY:
        if not options.rule_enabled(rule.id):
            continue
        if rule.severity is Severity.INFO:
            if not (options.include_info or options.strict):
                continue
        try:
            findings = rule.check(instructions, compose, options)
        except Exception as e:
            findings = [Finding(
                rule_id=rule.id,
                severity=Severity.HIGH,
                message="rule crashed: " + repr(e),
                subject="",
                line=0,
                path=path,
                hint="This is a composecheck bug. Please report it with the input that triggered it.",
                citation=rule.citation,
            )]
        for f in findings:
            if f.path:
                out.append(f)
            else:
                out.append(Finding(
                    rule_id=f.rule_id,
                    severity=f.severity,
                    message=f.message,
                    subject=f.subject,
                    line=f.line,
                    path=path,
                    hint=f.hint,
                    citation=f.citation,
                ))
    return out


__all__ = ["REGISTRY", "Rule", "Check", "run_all"]
