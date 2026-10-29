# composecheck

Static hardening linter for `Dockerfile` and `docker-compose` files.
Reads a `Dockerfile` and / or a `docker-compose.yml` the developer has
saved and reports posture defects against public container-security
guidance - CIS Docker Benchmark (sections 4 and 5), NIST SP 800-190
(Application Container Security Guide, sections 3.4 and 4.4), the
OWASP Docker Top 10, and MITRE CWE-250 / 732 / 798. Zero dependencies,
Python 3.9+.

Part of [defense-lab](https://github.com/epimystic-dev/defense-lab).

## What it is - and what it is not

- **It is**: a parser-plus-rulepack that reads two file surfaces
  (`Dockerfile`, `docker-compose.yml`) and emits findings keyed by
  rule id, with a public control (CIS Docker Benchmark section, NIST
  SP 800-190 section, OWASP Docker Top 10 id, CWE id) on every rule.
- **It is not**: a container runtime scanner, image scanner, or
  Docker-daemon client. composecheck never pulls an image, never
  builds a container, never connects to a Docker daemon. A clean run
  on your saved files does not prove the running container is
  hardened; it means **the committed files do not match any rule**.
  The image may still contain unpatched packages, the runtime may
  override compose settings via docker run flags, and the host may
  grant privileges the compose file does not request. Verify the
  running state separately.

## Install

```
python -m pip install -e .
```

Standard library only; no `pip install` is required for a one-off run
if you keep this folder on `PYTHONPATH`.

## Run

```
# Scan one Dockerfile:
python -m composecheck Dockerfile

# Scan one compose file:
python -m composecheck docker-compose.yml

# Scan a directory (every file whose name matches a Dockerfile or
# compose-file pattern is picked up):
python -m composecheck ./deploy/

# Force a file to be treated as a given kind (useful when the file
# name does not match a canonical pattern):
python -m composecheck --as dockerfile  my-build-recipe
python -m composecheck --as compose     stack.yaml

# JSON output:
python -m composecheck --json Dockerfile > posture.json

# Surface INFO rules and treat INFO-only outcomes as needs-attention:
python -m composecheck --strict Dockerfile

# Disable or isolate a rule:
python -m composecheck --disable DKF-008 Dockerfile
python -m composecheck --only  DC-001   docker-compose.yml
```

The CLI exits:

- `0` healthy
- `1` needs-attention (MEDIUM findings only, or INFO under `--strict`)
- `2` unhealthy (any HIGH finding, or unreadable input)

Results go to stdout; diagnostics go to stderr, so `--json` output can
be piped into another tool unread.

## Rules

Every rule cites the public control it implements. The citation is
printed alongside each finding under `cite:`.

### Dockerfile (DKF-prefix)

| ID | Severity | What it catches | Citation |
|---|---|---|---|
| DKF-001 | HIGH | Dockerfile has no `USER` directive, or the final `USER` is `0` / `root` | CIS Docker Benchmark 4.1; CWE-250 |
| DKF-002 | HIGH | `FROM` uses `:latest` or has no tag (floating image reference) | CIS Docker Benchmark 4.2 |
| DKF-003 | MEDIUM | `ADD` used for a local file (`COPY` is preferred; `ADD` has side effects) | CIS Docker Benchmark 4.9 |
| DKF-004 | MEDIUM | `apt-get install` missing `--no-install-recommends` or `rm -rf /var/lib/apt/lists/*` | CIS Docker Benchmark 4.3; 4.7 |
| DKF-005 | HIGH | `ENV` declares a secret-shaped variable (PASSWORD / TOKEN / API_KEY / SECRET / ...) | CIS Docker Benchmark 4.10; CWE-798 |
| DKF-006 | MEDIUM | `RUN` pipes `curl` / `wget` output into a shell | OWASP Docker Top 10 D04 |
| DKF-007 | HIGH | `RUN` uses `sudo` (Dockerfile builds already run as root) | CIS Docker Benchmark 4.1 companion |
| DKF-008 | INFO | Dockerfile has no `HEALTHCHECK` | CIS Docker Benchmark 4.6 |
| DKF-009 | HIGH | `RUN` sets world-writable permissions (`chmod 777` / `a=rwx`) | CWE-732 |
| DKF-010 | MEDIUM | `COPY` / `ADD` / `RUN` explicitly chown-s content to root | CIS Docker Benchmark 4.1 |

### docker-compose (DC-prefix)

| ID | Severity | What it catches | Citation |
|---|---|---|---|
| DC-001 | HIGH | Service runs with `privileged: true` | NIST SP 800-190 section 4.4.5; CIS Docker Benchmark 5.4 |
| DC-002 | HIGH | Service uses `network_mode: host` | CIS Docker Benchmark 5.9; NIST SP 800-190 section 4.4.3 |
| DC-003 | HIGH | Service shares the host `pid` or `ipc` namespace | CIS Docker Benchmark 5.9 / 5.10 |
| DC-004 | HIGH | Service adds a sensitive Linux capability (`SYS_ADMIN`, `NET_ADMIN`, `SYS_PTRACE`, `SYS_MODULE`, `SYS_RAWIO`, `NET_RAW`, `DAC_READ_SEARCH`, `DAC_OVERRIDE`, `ALL`) | CIS Docker Benchmark 5.3; CWE-250 |
| DC-005 | MEDIUM | Service does not drop `ALL` capabilities (recommended posture is `cap_drop: [ALL]` + targeted `cap_add`) | CIS Docker Benchmark 5.3 |
| DC-006 | HIGH | Service bind-mounts the Docker socket (`/var/run/docker.sock`) | CIS Docker Benchmark 5.31; OWASP Docker Top 10 D02 |
| DC-007 | HIGH | Service hard-codes a secret-shaped environment value (not a `${VAR}` reference) | CIS Docker Benchmark 5.3; CWE-798 |
| DC-008 | MEDIUM | Service has no `user:` or sets `user: root` | CIS Docker Benchmark 4.1 |
| DC-009 | MEDIUM | Service has no resource limits (`mem_limit`, `cpus`, or `deploy.resources.limits`) | CIS Docker Benchmark 5.11; NIST SP 800-190 section 4.4.6 |
| DC-010 | HIGH | Service weakens `security_opt` (`seccomp:unconfined`, `apparmor:unconfined`, `no-new-privileges:false`) | CIS Docker Benchmark 5.21; 5.1 |

An internal rule `COMPOSE-000` surfaces IO errors and unknown file
kinds as a HIGH finding so every result shares one verdict rollup.

## Honest scope

- composecheck reads **saved files**. If the Dockerfile is overridden
  at build time (BuildKit `--build-arg`, `--target`), or the compose
  file is composed with `-f` overlays at `docker compose up`, the
  effective posture may differ. Pass each file explicitly for the
  overlay you care about.
- The compose parser is a **shape** parser, not a full YAML parser.
  It handles the subset of YAML that compose files commonly use:
  nested mappings, scalars, sequences, inline mappings in sequences
  with continuation. Flow syntax (`[a, b]`, `{a: 1}`), block scalars
  (`|`, `>`), YAML anchors and tags are tolerated but not interpreted
  semantically. A file that relies on those shapes may silence a rule.
- DC-005, DC-008, DC-009 fire on a service with no sign of the
  recommended posture. They do not model all the ways the posture
  can be inherited (`extends:`, docker-compose override files,
  `common` services). Pass each file explicitly for the full picture.
- DC-010 flags only the specific unsafe strings; it does not try to
  parse every possible security-opt syntax. If your deployment
  relies on an unusual security-opt form, open an issue with a
  shape sample.

## False-positive modes

- **DKF-008 (missing HEALTHCHECK)**: many base images declare their
  own HEALTHCHECK that your Dockerfile inherits. composecheck cannot
  see into the parent image. If your base image already has one,
  use `--disable DKF-008`.
- **DKF-004 (apt hygiene)**: your organisation may have a reason to
  keep the apt lists (debugging). Use `--disable DKF-004` and record
  the exception in your own policy.
- **DC-009 (resource limits)**: Kubernetes-targeted compose files
  often omit `mem_limit` / `cpus` because the orchestrator sets them.
  Use `--disable DC-009` if your deployment target enforces limits
  elsewhere.
- **DC-007 (secret-shaped env)**: a `${VAR}` or `$VAR` reference is
  not flagged, but a value like `${VAR:-defaultvalue}` whose default
  contains a plausible secret is. composecheck does not try to
  distinguish; use `--disable DC-007` for that service or move the
  default to the host env.

## A tool like this exists because

Container-image and container-service posture is the single most-
common defender gap on developer-authored deployments, and the fix
lives in the file the developer has already committed. CIS Docker
Benchmark, NIST SP 800-190, and OWASP Docker Top 10 are stable public
documents that defenders already cite; composecheck turns their
recommendations into a `grep`-able rulepack. It does not replace an
image-SBOM scanner, a running-container audit, or a runtime policy
engine; it catches the shape defects **before** any of those run.

## Clean room

This is an **independent implementation**, not affiliated with or
endorsed by the Center for Internet Security, NIST, OWASP, MITRE, or
Docker Inc., nor by the authors of any other container-image or
compose linter. The rules are derived from the public text of the
CIS Docker Benchmark (sections 4 and 5), NIST SP 800-190 (sections
3.4 and 4.4), the public OWASP Docker Top 10 project pages, the
MITRE CWE-250 / 732 / 798 pages, and the public Docker reference
documentation for the Dockerfile instruction set and the
docker-compose file (versions 3 and 3.8); no reference implementation
of any container-image or compose linter was read, vendored, or
mirrored.

## License

MIT. See `LICENSE`.
