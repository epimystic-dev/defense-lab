# defense-lab

Small offline utilities for defenders, built only from public standards, that read an operator's own saved configuration and output files.

> Part of [Epimystic](https://epimystic.com) - a codex of the knowable and the unknowable.
> One of a family of labs: [`epimystic-lab`](https://github.com/epimystic-dev/epimystic-lab) / [`governance-lab`](https://github.com/epimystic-dev/governance-lab) / [`defense-lab`](https://github.com/epimystic-dev/defense-lab) / [`repro-lab`](https://github.com/epimystic-dev/repro-lab) / [`agent-guard-lab`](https://github.com/epimystic-dev/agent-guard-lab) / [`ai-ethics-lab`](https://github.com/epimystic-dev/ai-ethics-lab) / [`convergent-disciplines-lab`](https://github.com/epimystic-dev/convergent-disciplines-lab).

## What this is

A governed human-machine process scans the frontier each week and, *when something is
genuinely worth building*, produces one small, self-contained, tested artifact here. When
nothing clears the bar, it ships nothing but the radar entry - restraint is the quality gate.

- **`projects/`** - dated, self-contained micro-projects, each independently licensed,
  tested and documented.
- **`research-radar/`** - a dated digest of frontier signal: a few items each week with a
  one-line "why this matters", cited to source, and a note on what was built and why.

## What belongs here, and the boundary

Small offline utilities for defenders, built only from public standards (CIS Benchmarks,
OWASP, NIST SP 800-53 / 800-63B, Mozilla TLS guidance, CWE, CVE / OSV, SPDX / CycloneDX).
Each tool reads an operator's **own saved files** - a configuration they exported, a
response they captured, a lockfile they own - and reports posture defects with the public
control cited on every rule.

The boundary is a list, not a judgement call: no tool here connects to, scans or probes any
host, network or person; nothing fetches at runtime; there is no offensive capability of any
kind; fixtures contain no data about people. These tools help someone harden what they
already run. A clean run is not a security assessment.

## The tools currently published

Each folder has its own README, tests and LICENSE; click through for install and usage.

| Tool | What it does | Layer |
|---|---|---|
| [sshdcheck](projects/2026-10-18_sshdcheck/) | Static hardening linter for `sshd_config`: fifteen posture rules against CIS, Mozilla OpenSSH, and NIST SP 800-53. | linter |
| [headerscheck](projects/2026-10-18_headerscheck/) | Static security-header posture linter for saved HTTP responses: sixteen rules against OWASP Secure Headers, OWASP ASVS v4, RFC 6265bis, RFC 6797. | linter |
| [dnsrec](projects/2026-10-25_dnsrec/) | Static posture linter for SPF, DMARC, and DKIM DNS records: twenty-seven rules against RFC 7208, RFC 7489, RFC 6376, RFC 8463, NIST SP 800-177, and M3AAWG BCP. | linter |

*The radar publishes every Monday.*

## How it is made (and what that means)

Every artifact here is produced by **a human-machine hybrid intelligence, rooted in ethics
and philosophy**, and passes - *before* it is published - an external, deterministic policy
gate and an independent maker-checker review: a de-brand / secret gate, a clean-room rule (a
paper's method is read, never the authors' code), tests green under the public CI command,
and a claims-substantiation pass. The gate runs *outside* the builder. A passing gate means
**origin-valid, content-unverified**, never **verified-safe**. The engineering contract every
project meets is in [`docs/CONVENTIONS.md`](docs/CONVENTIONS.md).

## Honest scope

This is a research-and-utility lab, not a product. Artifacts are small by design;
reimplementations of published work are independent implementations, cited and **not
affiliated with or endorsed by the original authors**. Read each project's own README and
LICENSE.

## License

Each `projects/` artifact carries its own LICENSE (permissive; this lab's default is
MIT). The radar and this index are MIT.

---

*Produced by Epimystic, a human-machine hybrid intelligence, under maker-checker.*
