"""Rule registry for headerscheck.

Sixteen security-header posture rules on a captured HTTP response,
each citing the public control it implements. Rule IDs use the
``HDR-`` prefix; the lab-wide shared surface exposes this list as
``ALL_RULES``.

Rules are grounded in three public sources:

  * OWASP Secure Headers Project (owasp.org/www-project-secure-headers)
    - the baseline set of headers every production HTTPS site is
    recommended to carry, with per-header guidance.
  * OWASP ASVS v4, section V14.4 (HTTP Security Headers), and V3.4
    (Session Management - Cookies).
  * IETF RFC 6797 (HSTS), RFC 6265bis (cookies), and the CSP Level 3
    specification published by the W3C.

The rules capture SHAPE defects visible in the operator's saved
response; they do not test a live server. A clean run is origin-valid,
not verified-safe.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, List, Optional

from .parse import (
    Response,
    is_html_like,
    parse_cookie_attributes,
    parse_hsts_directives,
)
from .types import Finding, Options, Severity


Check = Callable[[Response, str, Options, dict], List[Finding]]


@dataclass(frozen=True)
class Rule:
    id: str
    severity: Severity
    title: str
    description: str
    citation: str
    check: Check


# ---------------------------------------------------------------------------
# Shared helpers.
# ---------------------------------------------------------------------------

# RFC 6797 recommends a max-age of at least 6 months (15552000 s) for
# any site intending to seriously commit to HTTPS; preload lists
# require a year (31536000 s). The OWASP Secure Headers Project
# documents the same threshold.
HSTS_MIN_MAX_AGE_SECONDS = 15552000


def _mk(
    rule_id: str,
    severity: Severity,
    message: str,
    header: str,
    path: str,
    hint: str,
    citation: str,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=severity,
        message=message,
        header=header,
        path=path,
        hint=hint,
        citation=citation,
    )


def _is_https(response: Response, options: Options) -> bool:
    if options.assume_https is True:
        return True
    if options.assume_https is False:
        return False
    if response.scheme == "https":
        return True
    if response.scheme == "http":
        return False
    # Unknown scheme - default to HTTPS, since the rules we gate on
    # scheme (HSTS, Secure cookies) are the ones the operator is most
    # likely to need to check.
    return True


# ---------------------------------------------------------------------------
# Rule implementations.
# ---------------------------------------------------------------------------

def _check_hsts_missing(response, path, options, context):
    citation = (
        "OWASP Secure Headers Project; IETF RFC 6797 (HSTS);"
        " OWASP ASVS v4 V14.4.5"
    )
    if not _is_https(response, options):
        return []
    if response.has("Strict-Transport-Security"):
        return []
    return [_mk(
        "HDR-001", Severity.HIGH,
        "Strict-Transport-Security header is missing on an HTTPS"
        " response",
        "Strict-Transport-Security", path,
        "add 'Strict-Transport-Security: max-age=31536000;"
        " includeSubDomains' (preload if the apex domain is ready)",
        citation,
    )]


def _check_hsts_max_age(response, path, options, context):
    citation = (
        "OWASP Secure Headers Project; IETF RFC 6797 section 6.1.1;"
        " below 15552000 (6 months) is not treated as a durable commit"
    )
    v = response.get("Strict-Transport-Security")
    if not v:
        return []
    d = parse_hsts_directives(v)
    raw = d.get("max-age")
    if raw is None:
        return [_mk(
            "HDR-002", Severity.MEDIUM,
            "Strict-Transport-Security has no max-age directive",
            "Strict-Transport-Security", path,
            "add 'max-age=31536000'",
            citation,
        )]
    try:
        n = int(raw)
    except ValueError:
        return [_mk(
            "HDR-002", Severity.MEDIUM,
            "Strict-Transport-Security max-age is not an integer: " + raw,
            "Strict-Transport-Security", path,
            "set max-age=31536000",
            citation,
        )]
    if n == 0:
        # max-age=0 is explicitly used to disable HSTS; flag HIGH.
        return [_mk(
            "HDR-002", Severity.HIGH,
            "Strict-Transport-Security max-age is 0 (HSTS disabled)",
            "Strict-Transport-Security", path,
            "set max-age=31536000; max-age=0 instructs the browser to"
            " discard its HSTS state",
            citation,
        )]
    if n < HSTS_MIN_MAX_AGE_SECONDS:
        return [_mk(
            "HDR-002", Severity.MEDIUM,
            "Strict-Transport-Security max-age is " + str(n) + " seconds"
            " (threshold " + str(HSTS_MIN_MAX_AGE_SECONDS) + ")",
            "Strict-Transport-Security", path,
            "raise max-age to at least 15552000 (6 months); 31536000"
            " (1 year) is the preload-list requirement",
            citation,
        )]
    return []


def _check_hsts_include_subdomains(response, path, options, context):
    citation = "OWASP Secure Headers Project"
    v = response.get("Strict-Transport-Security")
    if not v:
        return []
    d = parse_hsts_directives(v)
    if d.get("includesubdomains"):
        return []
    return [_mk(
        "HDR-003", Severity.INFO,
        "Strict-Transport-Security omits includeSubDomains",
        "Strict-Transport-Security", path,
        "add includeSubDomains to cover every subdomain of this host",
        citation,
    )]


def _check_hsts_preload(response, path, options, context):
    citation = "hstspreload.org eligibility criteria"
    v = response.get("Strict-Transport-Security")
    if not v:
        return []
    d = parse_hsts_directives(v)
    if d.get("preload"):
        return []
    return [_mk(
        "HDR-004", Severity.INFO,
        "Strict-Transport-Security omits preload",
        "Strict-Transport-Security", path,
        "add preload once max-age>=31536000 and includeSubDomains are"
        " in place, then submit at hstspreload.org",
        citation,
    )]


def _check_csp_missing(response, path, options, context):
    citation = "OWASP Secure Headers Project; OWASP ASVS v4 V14.4.3"
    if not is_html_like(response):
        return []
    if response.has("Content-Security-Policy"):
        return []
    return [_mk(
        "HDR-005", Severity.MEDIUM,
        "Content-Security-Policy header is missing on an HTML response",
        "Content-Security-Policy", path,
        "define a baseline policy: default-src 'self'; object-src 'none';"
        " base-uri 'none'; frame-ancestors 'none'",
        citation,
    )]


def _check_csp_unsafe(response, path, options, context):
    citation = (
        "W3C CSP Level 3 (unsafe-inline and unsafe-eval defeat XSS"
        " mitigation); OWASP Secure Headers Project"
    )
    v = response.get("Content-Security-Policy")
    if not v:
        return []
    lv = v.lower()
    bad: List[str] = []
    if "'unsafe-inline'" in lv:
        bad.append("'unsafe-inline'")
    if "'unsafe-eval'" in lv:
        bad.append("'unsafe-eval'")
    if "'unsafe-hashes'" in lv:
        bad.append("'unsafe-hashes'")
    if not bad:
        return []
    return [_mk(
        "HDR-006", Severity.HIGH,
        "Content-Security-Policy contains " + ", ".join(bad),
        "Content-Security-Policy", path,
        "replace 'unsafe-inline' with a nonce or hash-source; drop"
        " 'unsafe-eval' entirely",
        citation,
    )]


def _check_csp_wildcard_script(response, path, options, context):
    citation = "W3C CSP Level 3; a wildcard script-src accepts any origin"
    v = response.get("Content-Security-Policy")
    if not v:
        return []
    # Look at script-src (if present) OR default-src used as fallback.
    directives = _parse_csp_directives(v)
    src = directives.get("script-src") or directives.get("script-src-elem")
    if src is None:
        src = directives.get("default-src")
    if not src:
        return []
    # Flag an unqualified '*' token (not a scheme-constrained one like
    # 'https:' and not a specific host).
    if any(t == "*" for t in src):
        return [_mk(
            "HDR-007", Severity.MEDIUM,
            "Content-Security-Policy script-src accepts * (any origin)",
            "Content-Security-Policy", path,
            "replace '*' with a specific allowlist of script origins",
            citation,
        )]
    # Flag scheme-only wildcards for script-src (https:, http:, data:
    # all accept any host on that scheme).
    schemeish = [t for t in src if t.endswith(":")]
    if schemeish:
        return [_mk(
            "HDR-007", Severity.MEDIUM,
            "Content-Security-Policy script-src uses a scheme-only"
            " source (" + ", ".join(schemeish) + ")",
            "Content-Security-Policy", path,
            "replace scheme-only sources with specific host or"
            " nonce-based sources",
            citation,
        )]
    return []


def _check_x_content_type_options(response, path, options, context):
    citation = "OWASP Secure Headers Project; OWASP ASVS v4 V14.4.4"
    v = response.get("X-Content-Type-Options")
    if v.lower() == "nosniff":
        return []
    if v:
        return [_mk(
            "HDR-008", Severity.MEDIUM,
            "X-Content-Type-Options is not 'nosniff' (saw: " + v + ")",
            "X-Content-Type-Options", path,
            "set X-Content-Type-Options: nosniff",
            citation,
        )]
    return [_mk(
        "HDR-008", Severity.MEDIUM,
        "X-Content-Type-Options is missing",
        "X-Content-Type-Options", path,
        "set X-Content-Type-Options: nosniff",
        citation,
    )]


def _check_frame_protections(response, path, options, context):
    citation = (
        "OWASP Secure Headers Project; CSP frame-ancestors supersedes"
        " X-Frame-Options; one or the other must be present"
    )
    if not is_html_like(response):
        return []
    csp = response.get("Content-Security-Policy")
    xfo = response.get("X-Frame-Options")
    if csp:
        directives = _parse_csp_directives(csp)
        if "frame-ancestors" in directives:
            return []
    if xfo:
        return []
    return [_mk(
        "HDR-009", Severity.MEDIUM,
        "No clickjacking protection: neither X-Frame-Options nor"
        " CSP frame-ancestors is set",
        "X-Frame-Options", path,
        "set 'X-Frame-Options: DENY' or add 'frame-ancestors \\'none\\''"
        " to the CSP",
        citation,
    )]


def _check_referrer_policy(response, path, options, context):
    citation = "W3C Referrer Policy; OWASP Secure Headers Project"
    v = response.get("Referrer-Policy").lower()
    weak = {"", "unsafe-url", "no-referrer-when-downgrade"}
    if not v:
        return [_mk(
            "HDR-010", Severity.INFO,
            "Referrer-Policy is missing",
            "Referrer-Policy", path,
            "set Referrer-Policy: strict-origin-when-cross-origin"
            " (or no-referrer)",
            citation,
        )]
    if v in weak:
        return [_mk(
            "HDR-010", Severity.INFO,
            "Referrer-Policy is weak: " + v,
            "Referrer-Policy", path,
            "set Referrer-Policy: strict-origin-when-cross-origin",
            citation,
        )]
    return []


def _check_permissions_policy(response, path, options, context):
    citation = "W3C Permissions Policy; OWASP Secure Headers Project"
    if response.has("Permissions-Policy"):
        return []
    if not is_html_like(response):
        return []
    return [_mk(
        "HDR-011", Severity.INFO,
        "Permissions-Policy is missing",
        "Permissions-Policy", path,
        "declare a Permissions-Policy that denies features your page"
        " does not use (camera, microphone, geolocation, etc.)",
        citation,
    )]


def _check_server_banner(response, path, options, context):
    citation = "OWASP ASVS v4 V14.3.2 (disable verbose version banners)"
    out: List[Finding] = []
    server = response.get("Server")
    if server and _looks_versioned(server):
        out.append(_mk(
            "HDR-012", Severity.INFO,
            "Server header exposes a version banner: " + server,
            "Server", path,
            "remove or minimise the Server header; downstream intel"
            " does not need to know the exact version",
            citation,
        ))
    xp = response.get("X-Powered-By")
    if xp:
        out.append(_mk(
            "HDR-012", Severity.INFO,
            "X-Powered-By exposes an implementation banner: " + xp,
            "X-Powered-By", path,
            "remove X-Powered-By; the client has no business knowing"
            " the application framework",
            citation,
        ))
    return out


def _check_cookie_secure(response, path, options, context):
    citation = (
        "IETF RFC 6265bis section 5.5 (Secure attribute);"
        " OWASP ASVS v4 V3.4.1"
    )
    if not _is_https(response, options):
        return []
    out: List[Finding] = []
    for raw in response.get_all("Set-Cookie"):
        attrs = parse_cookie_attributes(raw)
        name = attrs.get("__name", "(unnamed)")
        if "secure" not in attrs:
            out.append(_mk(
                "HDR-013", Severity.HIGH,
                "Set-Cookie '" + name + "' on HTTPS is missing the Secure"
                " attribute",
                "Set-Cookie", path,
                "add Secure to every cookie set over HTTPS",
                citation,
            ))
    return out


def _check_cookie_httponly(response, path, options, context):
    citation = (
        "IETF RFC 6265bis section 5.6 (HttpOnly attribute);"
        " OWASP ASVS v4 V3.4.2"
    )
    out: List[Finding] = []
    for raw in response.get_all("Set-Cookie"):
        attrs = parse_cookie_attributes(raw)
        name = attrs.get("__name", "(unnamed)")
        if "httponly" not in attrs:
            out.append(_mk(
                "HDR-014", Severity.MEDIUM,
                "Set-Cookie '" + name + "' is missing the HttpOnly"
                " attribute",
                "Set-Cookie", path,
                "add HttpOnly to any cookie that does not need to be"
                " read by document.cookie",
                citation,
            ))
    return out


def _check_cookie_samesite(response, path, options, context):
    citation = (
        "IETF RFC 6265bis section 5.4 (SameSite attribute);"
        " OWASP ASVS v4 V3.4.3"
    )
    out: List[Finding] = []
    for raw in response.get_all("Set-Cookie"):
        attrs = parse_cookie_attributes(raw)
        name = attrs.get("__name", "(unnamed)")
        if "samesite" not in attrs:
            out.append(_mk(
                "HDR-015", Severity.MEDIUM,
                "Set-Cookie '" + name + "' is missing the SameSite"
                " attribute",
                "Set-Cookie", path,
                "add SameSite=Lax (or Strict), or SameSite=None;Secure"
                " only if third-party context is required",
                citation,
            ))
    return out


def _check_cors_credentials_wildcard(response, path, options, context):
    citation = (
        "Fetch Living Standard section 'CORS protocol'; W3C CORS;"
        " a wildcard with credentials is a specification-level"
        " contradiction"
    )
    aco = response.get("Access-Control-Allow-Origin")
    acc = response.get("Access-Control-Allow-Credentials").lower()
    if aco.strip() == "*" and acc == "true":
        return [_mk(
            "HDR-016", Severity.HIGH,
            "Access-Control-Allow-Origin is '*' and"
            " Access-Control-Allow-Credentials is true",
            "Access-Control-Allow-Origin", path,
            "echo a specific allowed origin instead of '*' when credentials"
            " are allowed; browsers refuse this combination at the"
            " network layer but the server posture is still wrong",
            citation,
        )]
    return []


# ---------------------------------------------------------------------------
# CSP parse helper.
# ---------------------------------------------------------------------------

def _parse_csp_directives(value: str) -> dict:
    """Return directive -> list[source] for a CSP header value."""
    out: dict = {}
    for part in value.split(";"):
        part = part.strip()
        if not part:
            continue
        tokens = part.split()
        if not tokens:
            continue
        name = tokens[0].lower()
        out[name] = tokens[1:]
    return out


def _looks_versioned(server: str) -> bool:
    """Return True if ``server`` carries a version-looking fragment,
    e.g. 'nginx/1.18.0' or 'Apache/2.4.41 (Ubuntu)'.
    """
    for ch in server:
        if ch.isdigit():
            return True
    return False


# ---------------------------------------------------------------------------
# Registry.
# ---------------------------------------------------------------------------

REGISTRY: List[Rule] = [
    Rule(
        id="HDR-001",
        severity=Severity.HIGH,
        title="Strict-Transport-Security is missing on HTTPS",
        description=(
            "Without HSTS, a downgrade attack can rewrite the client's"
            " request to HTTP."
        ),
        citation=(
            "OWASP Secure Headers Project; IETF RFC 6797; OWASP ASVS"
            " v4 V14.4.5"
        ),
        check=_check_hsts_missing,
    ),
    Rule(
        id="HDR-002",
        severity=Severity.MEDIUM,
        title="Strict-Transport-Security max-age is weak",
        description=(
            "A short max-age (or max-age=0, which disables HSTS) is"
            " not a durable commit."
        ),
        citation="OWASP Secure Headers Project; IETF RFC 6797 6.1.1",
        check=_check_hsts_max_age,
    ),
    Rule(
        id="HDR-003",
        severity=Severity.INFO,
        title="Strict-Transport-Security omits includeSubDomains",
        description=(
            "Without includeSubDomains, subdomains are not covered by"
            " the HSTS commit."
        ),
        citation="OWASP Secure Headers Project",
        check=_check_hsts_include_subdomains,
    ),
    Rule(
        id="HDR-004",
        severity=Severity.INFO,
        title="Strict-Transport-Security omits preload",
        description=(
            "preload is a prerequisite for inclusion in the browser"
            " HSTS preload list."
        ),
        citation="hstspreload.org eligibility criteria",
        check=_check_hsts_preload,
    ),
    Rule(
        id="HDR-005",
        severity=Severity.MEDIUM,
        title="Content-Security-Policy is missing on HTML",
        description=(
            "CSP is the only header that meaningfully mitigates XSS"
            " once it has reached the browser."
        ),
        citation="OWASP Secure Headers Project; OWASP ASVS v4 V14.4.3",
        check=_check_csp_missing,
    ),
    Rule(
        id="HDR-006",
        severity=Severity.HIGH,
        title="Content-Security-Policy contains unsafe-inline / unsafe-eval",
        description=(
            "unsafe-inline and unsafe-eval defeat CSP's XSS mitigation."
        ),
        citation="W3C CSP Level 3; OWASP Secure Headers Project",
        check=_check_csp_unsafe,
    ),
    Rule(
        id="HDR-007",
        severity=Severity.MEDIUM,
        title=(
            "Content-Security-Policy script-src accepts * or a"
            " scheme-only wildcard"
        ),
        description=(
            "A wildcard script-src accepts any origin, which collapses"
            " CSP's XSS mitigation."
        ),
        citation="W3C CSP Level 3",
        check=_check_csp_wildcard_script,
    ),
    Rule(
        id="HDR-008",
        severity=Severity.MEDIUM,
        title="X-Content-Type-Options is missing or not 'nosniff'",
        description=(
            "Without X-Content-Type-Options: nosniff, the browser may"
            " sniff a response's content type."
        ),
        citation="OWASP Secure Headers Project; OWASP ASVS v4 V14.4.4",
        check=_check_x_content_type_options,
    ),
    Rule(
        id="HDR-009",
        severity=Severity.MEDIUM,
        title="No clickjacking protection on HTML",
        description=(
            "Neither X-Frame-Options nor CSP frame-ancestors is set;"
            " the response is framable by any origin."
        ),
        citation="OWASP Secure Headers Project",
        check=_check_frame_protections,
    ),
    Rule(
        id="HDR-010",
        severity=Severity.INFO,
        title="Referrer-Policy is missing or weak",
        description=(
            "An absent or weak Referrer-Policy can leak request URLs"
            " cross-origin."
        ),
        citation="W3C Referrer Policy; OWASP Secure Headers Project",
        check=_check_referrer_policy,
    ),
    Rule(
        id="HDR-011",
        severity=Severity.INFO,
        title="Permissions-Policy is missing on HTML",
        description=(
            "Without a Permissions-Policy, the page inherits the"
            " browser default allow-set for every feature."
        ),
        citation="W3C Permissions Policy; OWASP Secure Headers Project",
        check=_check_permissions_policy,
    ),
    Rule(
        id="HDR-012",
        severity=Severity.INFO,
        title="Server / X-Powered-By exposes a version banner",
        description=(
            "A versioned Server header or an X-Powered-By line reveals"
            " implementation detail with no benefit to the client."
        ),
        citation="OWASP ASVS v4 V14.3.2",
        check=_check_server_banner,
    ),
    Rule(
        id="HDR-013",
        severity=Severity.HIGH,
        title="Set-Cookie on HTTPS is missing Secure",
        description=(
            "A cookie set without Secure can be captured over an"
            " unencrypted protocol downgrade."
        ),
        citation="IETF RFC 6265bis section 5.5; OWASP ASVS v4 V3.4.1",
        check=_check_cookie_secure,
    ),
    Rule(
        id="HDR-014",
        severity=Severity.MEDIUM,
        title="Set-Cookie is missing HttpOnly",
        description=(
            "A cookie without HttpOnly is reachable from"
            " document.cookie and widens the XSS impact surface."
        ),
        citation="IETF RFC 6265bis section 5.6; OWASP ASVS v4 V3.4.2",
        check=_check_cookie_httponly,
    ),
    Rule(
        id="HDR-015",
        severity=Severity.MEDIUM,
        title="Set-Cookie is missing SameSite",
        description=(
            "An absent SameSite attribute leaves the cookie attached"
            " to cross-site requests under legacy browser rules."
        ),
        citation="IETF RFC 6265bis section 5.4; OWASP ASVS v4 V3.4.3",
        check=_check_cookie_samesite,
    ),
    Rule(
        id="HDR-016",
        severity=Severity.HIGH,
        title=(
            "Access-Control-Allow-Origin is * with"
            " Access-Control-Allow-Credentials: true"
        ),
        description=(
            "The spec rejects this combination at the network layer,"
            " but the server posture is still misconfigured."
        ),
        citation="Fetch Living Standard; W3C CORS",
        check=_check_cors_credentials_wildcard,
    ),
]


def run_all(
    response: Response,
    path: str,
    options: Options,
) -> List[Finding]:
    out: List[Finding] = []
    context: dict = {}
    for rule in REGISTRY:
        if not options.rule_enabled(rule.id):
            continue
        if rule.severity is Severity.INFO and not (
            options.strict or options.include_info
        ):
            continue
        out.extend(rule.check(response, path, options, context))
    out.sort(key=lambda f: (f.path, f.rule_id))
    return out


__all__ = ["Rule", "Check", "REGISTRY", "run_all"]
