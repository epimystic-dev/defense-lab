# sshdcheck

Static hardening linter for sshd_config files. Reads an OpenSSH
`sshd_config` the operator has saved and reports posture defects
against public hardening guidance - CIS Benchmark for Linux
Distributions section 5.2, the Mozilla OpenSSH Guidelines, and NIST
SP 800-53 Revision 5. Zero dependencies, Python 3.9+.

Part of [defense-lab](https://github.com/epimystic-dev/defense-lab).

## What it is - and what it is not

- **It is**: a parser-plus-rulepack that reads one file surface
  (`sshd_config`) and emits findings keyed by rule id, with a public
  control (CIS section, Mozilla guideline, NIST control, CWE id) on
  every rule.
- **It is not**: a live SSH scanner. sshdcheck never connects to any
  host, service, network or user. It never fetches anything at
  runtime. It never tests credentials. A clean run on your sshd_config
  does not prove the running sshd is hardened; it means **the saved
  file does not match any rule**. The sshd process may be loading a
  different config (an `Include` directive, a packaging override, a
  config-management template). Verify the live server separately.

## Install

```
python -m pip install -e .
```

Standard library only; no `pip install` is required for a one-off run
if you keep this folder on `PYTHONPATH`.

## Run

```
python -m sshdcheck /etc/ssh/sshd_config
python -m sshdcheck --json /etc/ssh/sshd_config > posture.json
python -m sshdcheck --strict /etc/ssh/sshd_config    # surface INFO
python -m sshdcheck --only SSH-002 /etc/ssh/sshd_config
python -m sshdcheck --disable SSH-005 /etc/ssh/sshd_config
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

| ID | Severity | What it catches | Citation |
|---|---|---|---|
| SSH-001 | HIGH | PermitRootLogin is `yes` or unspecified | CIS 5.2.7; NIST SP 800-53 AC-6(2) |
| SSH-002 | HIGH | PasswordAuthentication is `yes` or unspecified | CIS 5.2.9; NIST SP 800-63B |
| SSH-003 | HIGH | PermitEmptyPasswords is `yes` | CIS 5.2.11 |
| SSH-004 | HIGH | Protocol declares SSH protocol 1 | CIS 5.2.1; CWE-327 |
| SSH-005 | MEDIUM | X11Forwarding is `yes` | CIS 5.2.4 |
| SSH-006 | MEDIUM | MaxAuthTries exceeds 4 | CIS 5.2.5 |
| SSH-007 | MEDIUM / HIGH | LoginGraceTime exceeds 60s (HIGH when 0) | CIS 5.2.17 |
| SSH-008 | MEDIUM | ClientAliveInterval 0 / missing or ClientAliveCountMax > 3 | CIS 5.2.18 / 5.2.19 |
| SSH-009 | HIGH | HostbasedAuthentication is `yes` | CIS 5.2.8; NIST SP 800-53 IA-2 |
| SSH-010 | MEDIUM | IgnoreRhosts is `no` or unspecified | CIS 5.2.7 |
| SSH-011 | HIGH | Ciphers contains a value outside the Mozilla modern allowlist | Mozilla OpenSSH Guidelines |
| SSH-012 | HIGH | MACs contains a value outside the Mozilla modern allowlist | Mozilla OpenSSH Guidelines; CWE-327 |
| SSH-013 | HIGH | KexAlgorithms contains a value outside the Mozilla modern allowlist | Mozilla OpenSSH Guidelines; CWE-327 |
| SSH-014 | INFO | LogLevel is below INFO | CIS 5.2.3; NIST SP 800-53 AU-2 |
| SSH-015 | MEDIUM | UsePAM is `no` | CIS 5.2.14 |

An internal rule `SSH-000` surfaces IO errors as a HIGH finding so
every result shares one verdict rollup.

## Honest scope

- The rules fire on the **saved file surface**. If a packaging drop-in
  (`/etc/ssh/sshd_config.d/*.conf`), an `Include` directive, or a
  config-management overlay overrides a global setting at runtime,
  sshdcheck does not see it. Pass each file explicitly to catch the
  override, or verify the live config with `sshd -T` outside sshdcheck.
- `Match` blocks: once a `Match` directive appears, every subsequent
  directive is scoped to that match. sshdcheck reports global
  (pre-`Match`) directives, not the match-scoped overrides, to avoid
  false confidence.
- Mozilla's modern-cipher / modern-MAC / modern-KEX allowlists are
  conservative. If your organisation has a documented reason to allow
  a non-modern value, use `--disable <RULE_ID>` and record the
  exception in your own policy.

## False-positive modes

- **Prefix modifiers (`+`, `-`, `^`)** on `Ciphers` / `MACs` /
  `KexAlgorithms` emit an INFO finding rather than HIGH, because the
  effective posture depends on the compile-time default and is not
  pinned in the file.
- **Match-scoped overrides** are intentionally not evaluated. A posture
  weakness that only applies inside a `Match User git` block does not
  fire; this is a documented limitation, not a bug.
- **PermitRootLogin forced-commands-only** is accepted as clean. If
  your policy forbids every form of root login, use `--only SSH-001`
  with `--strict`.

## A tool like this exists because

Default OpenSSH server configurations ship permissive settings - root
login allowed, password authentication on, weak cipher defaults
inherited from compile-time, no session idle timeout. CIS Linux
Benchmark revisions through 2026 continue to flag the same list; the
hardening-posture gap is a configuration-pinning problem, not a
knowledge problem. sshdcheck pins the posture in a form the operator
can grep.

## Clean room

This is an **independent implementation**, not affiliated with or
endorsed by the authors of CIS, Mozilla, NIST, OpenSSH, or any
other ssh-hardening tool. The rules are derived from the public
documents named above and from the public `sshd_config(5)` manual
page; no reference implementation of any ssh-hardening scanner was
read, vendored, or mirrored.

## License

MIT. See `LICENSE`.
