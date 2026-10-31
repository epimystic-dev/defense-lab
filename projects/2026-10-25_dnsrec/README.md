# dnsrec

Static posture linter for SPF, DMARC, and DKIM DNS records. Reads a
BIND-style zone file (or a one-record-per-line TXT export) the operator
has saved and reports posture defects against public email-
authentication guidance - IETF RFC 7208 (SPF), RFC 7489 (DMARC),
RFC 6376 (DKIM), RFC 8463 (DKIM Ed25519), NIST SP 800-177 Revision 1,
and the M3AAWG Email Authentication Best Common Practices. Zero
dependencies, Python 3.9+.

Part of [defense-lab](https://github.com/epimystic-dev/defense-lab).

## What it is - and what it is not

- **It is**: a parser-plus-rulepack that reads one file surface
  (a zone file or a bare TXT dump) and emits findings keyed by rule
  id, with a public control (RFC section, NIST control, M3AAWG BCP)
  on every rule.
- **It is not**: a live DNS or email scanner. dnsrec never queries any
  DNS server, SMTP server, or report-URI endpoint. It never fetches
  anything at runtime. It never tests credentials. A clean run on your
  zone file does not prove live mail flow is authenticated; it means
  **the saved record text does not match any rule**. The published
  record at your authoritative server may differ (zone-serial mismatch,
  record not yet propagated, a mail provider overlay). Verify the live
  state separately with `dig TXT <name>`.

## Install

```
python -m pip install -e .
```

Standard library only; no `pip install` is required for a one-off run
if you keep this folder on `PYTHONPATH`.

## Run

```
# A BIND-style zone-file snippet with SPF / DMARC / DKIM records:
python -m dnsrec example.invalid.zone

# JSON output (diagnostics on stderr, so the stream is parse-safe):
python -m dnsrec --json example.invalid.zone > posture.json

# Each line of the file is a bare TXT value for the declared kind
# (useful for feeding `dig +short TXT ...` output):
python -m dnsrec --kind dmarc dmarc-record.txt
python -m dnsrec --kind spf spf-record.txt
python -m dnsrec --kind dkim dkim-selector.txt

# Surface INFO rules and treat INFO-only outcomes as needs-attention:
python -m dnsrec --strict example.invalid.zone

# Disable or isolate a rule:
python -m dnsrec --disable DMARC-006 example.invalid.zone
python -m dnsrec --only  SPF-002   example.invalid.zone
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

### SPF (RFC 7208)

| ID | Severity | What it catches | Citation |
|---|---|---|---|
| SPF-001 | HIGH | Multiple SPF records at the same owner | RFC 7208 section 3.2 |
| SPF-002 | HIGH | SPF record exceeds the ten-DNS-lookup cap (include / a / mx / ptr / exists / redirect combined) | RFC 7208 section 4.6.4 |
| SPF-003 | HIGH | SPF ends with `+all` or `?all` (permissive default) | RFC 7208 section 4.6.4 |
| SPF-004 | MEDIUM | SPF ends with `~all` (soft fail; M3AAWG BCP recommends `-all`) | M3AAWG BCP |
| SPF-005 | HIGH | SPF has no `all` mechanism (defaults to neutral) | RFC 7208 section 4.7 |
| SPF-006 | MEDIUM | SPF uses the deprecated `ptr` mechanism | RFC 7208 section 5.5 |
| SPF-007 | INFO | SPF logical body exceeds a single 255-byte TXT quoted string | RFC 1035 section 3.3.14 |
| SPF-008 | HIGH | SPF-shaped record does not begin with `v=spf1` | RFC 7208 section 4.5 |
| SPF-009 | MEDIUM | SPF contains an any-source wildcard (`+ip4:0.0.0.0/0` or `+ip6:::/0`) | NIST SP 800-177 section 4.6.1 |
| SPF-010 | HIGH | SPF version section `v=spf1` is not followed by whitespace (e.g. `v=spf1-all`, `v=spf1include:...`); receivers discard the record | RFC 7208 section 4.5; Appendix A |

### DMARC (RFC 7489)

| ID | Severity | What it catches | Citation |
|---|---|---|---|
| DMARC-001 | HIGH | DMARC policy is `p=none` (monitor only; non-enforcing) | RFC 7489 section 6.3; NIST SP 800-177 section 4.6.2 |
| DMARC-002 | MEDIUM | DMARC policy is `p=quarantine` (intermediate; recommend `p=reject`) | NIST SP 800-177 section 4.6.2 |
| DMARC-003 | HIGH | DMARC record is missing the required `p=` tag | RFC 7489 section 6.3 |
| DMARC-004 | HIGH | DMARC-shaped record does not begin with `v=DMARC1` | RFC 7489 section 6.3 |
| DMARC-005 | HIGH | `pct<100` (partial deployment; sampled enforcement) | RFC 7489 section 6.3 |
| DMARC-006 | MEDIUM | `adkim=r` or absent (relaxed DKIM alignment) | RFC 7489 section 6.3 |
| DMARC-007 | MEDIUM | `aspf=r` or absent (relaxed SPF alignment) | RFC 7489 section 6.3 |
| DMARC-008 | HIGH | DMARC record has no `rua=` aggregate reporting URI | M3AAWG BCP; NIST SP 800-177 section 4.6.2 |
| DMARC-009 | HIGH | `sp=` is weaker than `p=` (sub-domain policy loosens the parent) | RFC 7489 section 6.3 |
| DMARC-010 | HIGH | DMARC record is not published at `_dmarc.<domain>` | RFC 7489 section 6.1 |
| DMARC-011 | HIGH | `p=` value is not one of `none`, `quarantine`, `reject` (receivers skip DMARC per section 6.6.3) | RFC 7489 section 6.3; section 6.6.3 |

### DKIM (RFC 6376, RFC 8463)

| ID | Severity | What it catches | Citation |
|---|---|---|---|
| DKIM-001 | HIGH | `v=` tag is present but is not `DKIM1` | RFC 6376 section 3.6.1 |
| DKIM-002 | HIGH | Key type `k=` is not `rsa` or `ed25519` | RFC 6376 section 3.6.1; RFC 8463 |
| DKIM-003 | HIGH | `p=` is empty (key revoked) | RFC 6376 section 3.6.1 |
| DKIM-004 | HIGH | RSA public key is below 2048 bits | NIST SP 800-131A; M3AAWG BCP |
| DKIM-005 | MEDIUM | Testing-mode flag `t=y` is set | RFC 6376 section 3.6.1 |
| DKIM-006 | INFO | Obsolete `g=` granularity tag is present (removed in RFC 6376) | RFC 6376 section 3.6.1 |
| DKIM-007 | HIGH | `p=` value is not valid base64 | RFC 6376 section 3.6.1; RFC 4648 |
| DKIM-008 | HIGH | DKIM record is not published under `._domainkey.<domain>` | RFC 6376 section 3.6.2.1 |
| DKIM-009 | HIGH | DKIM record is missing the required `p=` tag (no key published; different from `p=` empty, which is explicit revocation) | RFC 6376 section 3.6.1 |

An internal rule `DNSREC-000` surfaces IO errors as a HIGH finding so
every result shares one verdict rollup.

## Honest scope

- dnsrec reads a **saved file**. If the authoritative server returns
  a different record (uncommitted zone-serial change, DNSSEC takeover,
  provider-level overlay), dnsrec cannot see it. Verify the live state
  with `dig TXT` on the authoritative server and feed its output back
  through `--kind` for a point-in-time check.
- The 10-lookup counter counts tokens visible in the saved record;
  `include:_spf.example.net` counts once at the file level, but the
  nested record it points to can itself contain lookups that exhaust
  the cap at validation time. dnsrec cannot see into an include
  without being told to; a passing SPF-002 is a necessary condition,
  not a sufficient one.
- DMARC-003 and DMARC-004 are mutually exclusive by design: a record
  with the wrong `v=` is already flagged by DMARC-004, so DMARC-003
  skips it to avoid double-reporting.
- `--kind` mode synthesises an owner name (`example.invalid`,
  `_dmarc.example.invalid`, `selector._domainkey.example.invalid`),
  so DMARC-010 and DKIM-008 (owner-position rules) will not fire in
  that mode. Pass a zone file for those checks.

## False-positive modes

- **DMARC-006 / DMARC-007 default-value firings**: a record without
  `adkim=` or `aspf=` defaults to relaxed per RFC 7489 section 6.3.
  Many operators treat the default as acceptable. If your policy
  accepts relaxed alignment, use `--disable DMARC-006 DMARC-007` and
  record the exception in your own policy.
- **DKIM-004 skipped on non-RSA keys**: an ed25519 selector will not
  fire DKIM-004 (bit-length does not apply). This is intentional per
  RFC 8463.
- **DMARC-010 misfires on wildcard apex zones**: if your zone file
  uses `*.<domain>._dmarc` for sub-domain delegation, dnsrec treats
  the owner literally. Dis-shape fixes vary by provider; verify at
  the apex record.

## A tool like this exists because

Email-authentication posture is the biggest "defender gap that lives
in a file the operator already owns" that still sees daily rollouts of
mail infrastructure with `p=none`, `pct=50`, missing `rua=`,
1024-bit DKIM selectors, and SPF records that silently exceed the
ten-lookup cap. The 2024 bulk-sender enforcement wave at major
mailbox providers made the posture visible at the inbox but did not
make it visible in the operator's zone editor. dnsrec pins the
posture in a form the operator can grep.

## Clean room

This is an **independent implementation**, not affiliated with or
endorsed by the IETF, NIST, M3AAWG, or any mailbox provider, nor by
the authors of any other DNS or email-authentication linter. The
rules are derived from the public text of IETF RFC 7208, RFC 7489,
RFC 6376, RFC 8463, RFC 1035, RFC 4648, NIST SP 800-177 Revision 1,
NIST SP 800-131A, and the public M3AAWG Email Authentication Best
Common Practices; no reference implementation of any DNS or email-
authentication linter was read, vendored, or mirrored.

## License

MIT. See `LICENSE`.
