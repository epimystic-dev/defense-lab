# headerscheck

Static security-header posture linter for saved HTTP responses. Reads
a raw HTTP response, a headers-only file (what `curl -D` writes), or
a HAR entry the operator has captured, and reports posture defects
against the OWASP Secure Headers Project baseline, OWASP ASVS v4
sections V3.4 and V14.4, IETF RFC 6265bis (cookies), RFC 6797
(HSTS), and the W3C Content Security Policy Level 3 draft. Zero
dependencies, Python 3.9+.

Part of [defense-lab](https://github.com/epimystic-dev/defense-lab).

## What it is - and what it is not

- **It is**: a parser-plus-rulepack that reads one file surface (an
  HTTP response the operator has saved) and emits findings keyed by
  rule id, with the public control (OWASP section, RFC number, W3C
  draft) printed on every finding.
- **It is not**: a live web scanner. headerscheck never connects to
  any host, service, network or user. It never fetches anything at
  runtime. It never evaluates behaviour; it only reads header shape.
  A clean run on your captured response does not prove the running
  server is hardened: a different route, a different endpoint, or a
  different method may return a different header set. Capture the
  responses you care about and run headerscheck on each.

## Install

```
python -m pip install -e .
```

Standard library only.

## Capture a response, then lint it

```
# raw response (headers + body)
curl -i https://example.test/ > response.http

# headers only
curl -D headers.txt -o /dev/null https://example.test/

# HAR entries from your browser's DevTools "Save all as HAR with content"
```

## Run

```
python -m headerscheck response.http
python -m headerscheck --json headers.txt > posture.json
python -m headerscheck session.har       # treats each entry separately
python -m headerscheck --strict response.http
python -m headerscheck --assume-http response.http   # internal HTTP endpoint
python -m headerscheck --only HDR-006 response.http
python -m headerscheck --disable HDR-010 response.http
```

The CLI exits:

- `0` healthy
- `1` needs-attention (MEDIUM findings only, or INFO under `--strict`)
- `2` unhealthy (any HIGH finding, or unreadable input)

Results on stdout; diagnostics on stderr.

## Rules

Every rule cites the public control it implements. The citation
appears under `cite:` for every finding.

| ID | Severity | What it catches | Citation |
|---|---|---|---|
| HDR-001 | HIGH | Strict-Transport-Security is missing on an HTTPS response | OWASP Secure Headers; RFC 6797; ASVS V14.4.5 |
| HDR-002 | HIGH / MEDIUM | HSTS max-age is 0 (HIGH, disables HSTS) or below 15552000 (MEDIUM) | OWASP Secure Headers; RFC 6797 6.1.1 |
| HDR-003 | INFO | HSTS omits includeSubDomains | OWASP Secure Headers |
| HDR-004 | INFO | HSTS omits preload | hstspreload.org eligibility criteria |
| HDR-005 | MEDIUM | Content-Security-Policy is missing on an HTML response | OWASP Secure Headers; ASVS V14.4.3 |
| HDR-006 | HIGH | CSP contains `'unsafe-inline'`, `'unsafe-eval'`, or `'unsafe-hashes'` | W3C CSP Level 3; OWASP Secure Headers |
| HDR-007 | MEDIUM | CSP script-src accepts `*` or a scheme-only wildcard | W3C CSP Level 3 |
| HDR-008 | MEDIUM | X-Content-Type-Options is missing or not `nosniff` | OWASP Secure Headers; ASVS V14.4.4 |
| HDR-009 | MEDIUM | No clickjacking protection: neither X-Frame-Options nor CSP frame-ancestors | OWASP Secure Headers |
| HDR-010 | INFO | Referrer-Policy is missing or weak | W3C Referrer Policy; OWASP Secure Headers |
| HDR-011 | INFO | Permissions-Policy is missing on an HTML response | W3C Permissions Policy; OWASP Secure Headers |
| HDR-012 | INFO | Server / X-Powered-By exposes a version banner | OWASP ASVS v4 V14.3.2 |
| HDR-013 | HIGH | Set-Cookie on HTTPS is missing the Secure attribute | IETF RFC 6265bis 5.5; ASVS V3.4.1 |
| HDR-014 | MEDIUM | Set-Cookie is missing HttpOnly | IETF RFC 6265bis 5.6; ASVS V3.4.2 |
| HDR-015 | MEDIUM | Set-Cookie is missing SameSite | IETF RFC 6265bis 5.4; ASVS V3.4.3 |
| HDR-016 | HIGH | `Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true` | Fetch Living Standard; W3C CORS |

An internal rule `HDR-000` surfaces IO / parse errors as a HIGH
finding so every result shares one verdict rollup.

## Honest scope

- The rules fire on the **captured response surface**. A different
  route or endpoint on the same host may return a different header
  set. headerscheck does not infer coverage; capture the responses
  that matter.
- HTTPS inference: when a HAR entry URL is available, the scheme is
  taken from the URL. When captured as raw HTTP text with no URL
  (e.g. `curl -D`), the default is HTTPS. Override with
  `--assume-http` on internal endpoints that are legitimately HTTP.
- CSP semantics: the rules read directive shape, not CSP evaluation
  semantics. A nonce-based CSP with no explicit source list will
  satisfy HDR-005 but produce no verdict on whether the nonce is
  high-entropy; that is a browser-side property, outside file scope.
- Cookie attributes: the parser reads the first cookie name/value
  pair and every subsequent `; attribute` or `; attribute=value`.
  Non-standard cookie syntax (encoded commas, legacy folds) is
  tolerated, not deeply validated.

## False-positive modes

- **Headers-only captures with no URL** are treated as HTTPS. If your
  capture is an internal plaintext endpoint, pass `--assume-http`.
- **API responses that are not HTML** silently skip HDR-005 (CSP),
  HDR-009 (clickjacking), and HDR-011 (Permissions-Policy); CSP is a
  browser-rendering control, not an API control. If your API feeds
  HTML downstream, add those headers anyway and the rules fire again.
- **Server header with no version** (e.g. `Server: cloudflare`) is
  not flagged under HDR-012; the probe only triggers when the Server
  value carries a digit.

## A tool like this exists because

Response-header posture is one of the most common defensive gaps that
public standards (OWASP Top 10, OWASP ASVS v4, OWASP Web Security
Testing Guide 4.14) flag year after year, and it is one of the
easiest to miss in a configuration pipeline that focuses on
application code. Pinning the posture against a saved response makes
it a reviewable artifact.

## Clean room

This is an **independent implementation**, not affiliated with or
endorsed by OWASP, the W3C, the IETF, or any other HTTP-posture
scanner. The rules are derived from the public documents named
above; no reference implementation of any security-header scanner
was read, vendored, or mirrored.

## License

MIT. See `LICENSE`.
