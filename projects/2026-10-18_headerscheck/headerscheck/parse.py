"""File-shape parser for headerscheck.

Three input shapes are supported, matching how operators commonly save
an HTTP response:

  (a) Raw HTTP response text (what `curl -i` writes):

        HTTP/1.1 200 OK
        Content-Type: text/html
        Strict-Transport-Security: max-age=31536000

        <body...>

      The body is ignored. A leading request block is tolerated and
      skipped (the parser locks onto the FIRST non-request status line
      it finds).

  (b) Headers-only text (what `curl -D headers.txt` writes):

        HTTP/2 200
        content-type: text/html
        strict-transport-security: max-age=31536000

  (c) HAR (RFC 8392-ish) JSON. Either a HAR document (``{"log":
      {"entries": [...]}}``) or a single entry (``{"request": ...,
      "response": {...}}``), or a simple JSON object with a
      ``headers`` field that is either a dict or a list of
      ``{"name": ..., "value": ...}`` records.

Returns a list of ``Response`` objects. One file can carry many
responses (a HAR with many entries).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, List, Optional, Tuple


@dataclass(frozen=True)
class Response:
    """A single parsed HTTP response surface.

    ``headers`` preserves order and duplicates: HTTP allows a header
    to appear multiple times (e.g. several Set-Cookie), and the rules
    need to see every value.
    """

    url: Optional[str]
    status: Optional[int]
    headers: Tuple[Tuple[str, str], ...]
    # The URL scheme (http / https) if known from the HAR entry URL,
    # a Request-Line, or an explicit --assume-https option. None when
    # unknown.
    scheme: Optional[str] = None

    def get(self, name: str, default: str = "") -> str:
        """Return the FIRST header value for ``name`` (case-insensitive)."""
        lname = name.lower()
        for k, v in self.headers:
            if k.lower() == lname:
                return v
        return default

    def get_all(self, name: str) -> List[str]:
        """Return every value for ``name`` (case-insensitive)."""
        lname = name.lower()
        return [v for k, v in self.headers if k.lower() == lname]

    def has(self, name: str) -> bool:
        lname = name.lower()
        return any(k.lower() == lname for k, v in self.headers)


def _detect_shape(content: str) -> str:
    stripped = content.lstrip()
    if not stripped:
        return "empty"
    if stripped[0] in "{[":
        return "json"
    return "http"


def load(content: str) -> Tuple[List[Response], Optional[str]]:
    """Parse the full file text. Return (responses, error-message)."""
    shape = _detect_shape(content)
    if shape == "empty":
        return [], "file is empty"
    if shape == "json":
        try:
            doc = json.loads(content)
        except json.JSONDecodeError as e:
            return [], (
                "invalid JSON at line " + str(e.lineno) + " column "
                + str(e.colno) + ": " + e.msg
            )
        return _responses_from_json(doc), None
    return _responses_from_http(content)


_HTTP_METHODS = (
    "GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT",
    "OPTIONS", "TRACE", "PATCH",
)


def _is_request_line(line: str) -> bool:
    """Return True for ``METHOD <target> HTTP/x.y``."""
    parts = line.split()
    if len(parts) < 3:
        return False
    if parts[0] not in _HTTP_METHODS:
        return False
    return parts[-1].startswith("HTTP/")


def _responses_from_http(
    content: str,
) -> Tuple[List[Response], Optional[str]]:
    """Parse one or more HTTP responses from a text blob."""
    # Normalise line endings.
    lines = content.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    responses: List[Response] = []
    i = 0
    saw_any_status_line = any(line.startswith("HTTP/") for line in lines)
    while i < len(lines):
        # Skip blank lines between sections.
        while i < len(lines) and not lines[i].strip():
            i += 1
        if i >= len(lines):
            break
        # Skip a request block entirely (lines until the next blank).
        if _is_request_line(lines[i]):
            while i < len(lines) and lines[i].strip():
                i += 1
            continue
        if not lines[i].startswith("HTTP/"):
            # If the whole file never contains a status line, fall into
            # headers-only mode: treat the first run of headers as one
            # response.
            if not saw_any_status_line and ":" in lines[i]:
                headers, scheme, _idx = _read_headers(lines, i)
                responses.append(Response(
                    url=None, status=None,
                    headers=tuple(headers),
                    scheme=scheme,
                ))
                return responses, None
            # Otherwise this is body / malformed-section noise; skip.
            i += 1
            continue
        # Status line.
        status_line = lines[i]
        status = _parse_status(status_line)
        i += 1
        headers, scheme, i = _read_headers(lines, i)
        responses.append(Response(
            url=None, status=status,
            headers=tuple(headers),
            scheme=scheme,
        ))
        # Skip over any body up to the next status / request line or EOF.
        while i < len(lines) and not (
            lines[i].startswith("HTTP/")
            or _is_request_line(lines[i])
        ):
            i += 1
    if not responses:
        return [], (
            "no HTTP response status line or header found; is the file"
            " an HTTP response capture?"
        )
    return responses, None


def _parse_status(line: str) -> Optional[int]:
    """Status line is 'HTTP/x.y NNN [reason]'. HTTP/2 lines are
    'HTTP/2 NNN' with no reason phrase.
    """
    parts = line.split()
    if len(parts) < 2:
        return None
    try:
        return int(parts[1])
    except ValueError:
        return None


def _read_headers(
    lines: List[str], start: int
) -> Tuple[List[Tuple[str, str]], Optional[str], int]:
    """Read headers starting at ``start`` until a blank line or EOF.

    Returns (header pairs, scheme-if-known, next-index).
    """
    out: List[Tuple[str, str]] = []
    scheme: Optional[str] = None
    i = start
    pending: Optional[Tuple[str, str]] = None
    while i < len(lines):
        line = lines[i]
        if not line.strip():
            i += 1
            break
        # Folded continuation (deprecated but still seen).
        if line[:1] in (" ", "\t"):
            if pending is not None:
                pending = (pending[0], pending[1] + " " + line.strip())
            i += 1
            continue
        if pending is not None:
            out.append(pending)
            pending = None
        if ":" not in line:
            # Malformed header line - skip, do not crash. Downstream
            # rules work off the pairs we have.
            i += 1
            continue
        name, value = line.split(":", 1)
        name = name.strip()
        value = value.strip()
        pending = (name, value)
        i += 1
    if pending is not None:
        out.append(pending)
    return out, scheme, i


def _responses_from_json(doc: Any) -> List[Response]:
    """Extract responses from a HAR document or a header-blob JSON."""
    # HAR document.
    if isinstance(doc, dict) and isinstance(doc.get("log"), dict):
        entries = doc["log"].get("entries", [])
        return [_response_from_har_entry(e) for e in entries if isinstance(e, dict)]
    # Single HAR-style entry.
    if isinstance(doc, dict) and isinstance(doc.get("response"), dict):
        return [_response_from_har_entry(doc)]
    # Header-blob: {"url": "...", "headers": {...}}
    if isinstance(doc, dict) and "headers" in doc:
        headers = _normalise_headers_field(doc["headers"])
        url = doc.get("url") if isinstance(doc.get("url"), str) else None
        status = doc.get("status") if isinstance(doc.get("status"), int) else None
        scheme = _scheme_from_url(url) if url else None
        return [Response(
            url=url, status=status,
            headers=tuple(headers), scheme=scheme,
        )]
    # Array of header-blobs.
    if isinstance(doc, list):
        return [r for e in doc for r in _responses_from_json(e) if r]
    return []


def _response_from_har_entry(entry: dict) -> Response:
    resp = entry.get("response") or {}
    req = entry.get("request") or {}
    url = req.get("url") if isinstance(req.get("url"), str) else None
    status = resp.get("status") if isinstance(resp.get("status"), int) else None
    headers = _normalise_headers_field(resp.get("headers") or [])
    scheme = _scheme_from_url(url) if url else None
    return Response(
        url=url, status=status, headers=tuple(headers), scheme=scheme,
    )


def _normalise_headers_field(value: Any) -> List[Tuple[str, str]]:
    """Accept HAR-style list of {name, value} records OR dict mapping,
    return an ordered list of pairs.
    """
    if isinstance(value, list):
        out: List[Tuple[str, str]] = []
        for item in value:
            if isinstance(item, dict):
                name = item.get("name")
                val = item.get("value")
                if isinstance(name, str) and isinstance(val, str):
                    out.append((name, val))
        return out
    if isinstance(value, dict):
        out = []
        for k, v in value.items():
            if isinstance(k, str):
                if isinstance(v, list):
                    for sub in v:
                        if isinstance(sub, str):
                            out.append((k, sub))
                elif isinstance(v, str):
                    out.append((k, v))
        return out
    return []


def _scheme_from_url(url: str) -> Optional[str]:
    low = url.lower()
    if low.startswith("https://"):
        return "https"
    if low.startswith("http://"):
        return "http"
    return None


# ---------------------------------------------------------------------------
# Small shape helpers used by rules.
# ---------------------------------------------------------------------------

def is_html_like(response: Response) -> bool:
    """Return True when Content-Type suggests a browser-rendered
    document. Several header rules only make sense for HTML responses.
    """
    ct = response.get("Content-Type").lower()
    if not ct:
        return True   # unknown; treat as HTML for the safer default
    return (
        "html" in ct
        or "xhtml" in ct
        or "svg" in ct
    )


def parse_hsts_directives(value: str) -> dict:
    """Return a dict of HSTS directive -> value.

    Each HSTS directive is semicolon-separated; max-age is a bare
    integer. Example: ``max-age=31536000; includeSubDomains; preload``.
    """
    out: dict = {}
    for part in value.split(";"):
        part = part.strip()
        if not part:
            continue
        if "=" in part:
            k, v = part.split("=", 1)
            out[k.strip().lower()] = v.strip().strip('"')
        else:
            out[part.lower()] = True
    return out


def parse_cookie_attributes(value: str) -> dict:
    """Return a dict of cookie attribute -> value for a Set-Cookie
    header string. Case-insensitive on attribute names. The cookie
    name/value is stored under '__name' / '__value'.
    """
    out: dict = {}
    parts = [p.strip() for p in value.split(";")]
    if not parts:
        return out
    first = parts[0]
    if "=" in first:
        name, val = first.split("=", 1)
        out["__name"] = name.strip()
        out["__value"] = val.strip()
    for part in parts[1:]:
        if not part:
            continue
        if "=" in part:
            k, v = part.split("=", 1)
            out[k.strip().lower()] = v.strip()
        else:
            out[part.lower()] = True
    return out


__all__ = [
    "Response",
    "load",
    "is_html_like",
    "parse_hsts_directives",
    "parse_cookie_attributes",
]
