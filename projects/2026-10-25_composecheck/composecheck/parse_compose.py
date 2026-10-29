"""Minimal docker-compose shape parser.

This is NOT a full YAML parser. It walks a docker-compose file by
indentation and recognises the subset of shapes composecheck's rules
need:

  * A top-level mapping (``services:``, ``volumes:``, ``networks:``,
    ``version:``).
  * Nested mappings two or four spaces per indent level.
  * Scalar values ``key: value`` (quoted or unquoted).
  * Block mappings ``key:`` followed by nested indented keys.
  * Sequences ``- item`` or ``- key: value`` as list elements.
  * Line and inline ``#`` comments outside quoted strings.

What this parser does NOT handle:

  * Block scalars (``|``, ``>``). A block scalar body is captured as
    a plain-text concatenation; composecheck does not need the YAML
    semantics for its rules.
  * Flow mappings / sequences (``{a: 1, b: 2}``, ``[a, b]``). These
    are recorded as scalar strings; a rule that needs to see inside
    one of these should handle the brace / bracket form itself.
  * YAML tags and anchors (``&a``, ``*a``, ``!!tag``). These are
    passed through verbatim.

The parser returns a ``Service`` list plus a top-level ``Node`` tree.
A service is a direct child of the top-level ``services:`` key; its
properties are indexed on first use for easy rule queries.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple, Union


# ---------------------------------------------------------------------------
# Datatypes
# ---------------------------------------------------------------------------

@dataclass
class Scalar:
    """A scalar value with its source line number."""
    value: str
    line: int


# A tree node is either a Scalar, a Mapping (dict[str, Node]) or a
# Sequence (list[Node]).
Node = Union[Scalar, Dict[str, "Node"], List["Node"]]


@dataclass
class Service:
    """One docker-compose service entry under ``services:``."""
    name: str
    line: int
    body: Dict[str, Any] = field(default_factory=dict)

    def get(self, key: str, default: Any = None) -> Any:
        return self.body.get(key, default)

    def has(self, key: str) -> bool:
        return key in self.body

    def scalar(self, key: str) -> Optional[Scalar]:
        v = self.body.get(key)
        if isinstance(v, Scalar):
            return v
        return None

    def sequence(self, key: str) -> List[Any]:
        v = self.body.get(key)
        if isinstance(v, list):
            return v
        return []


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

_INDENT_RE = re.compile(r"^(\s*)")
_LIST_RE = re.compile(r"^-\s+(.*)$")
_LIST_ONLY_DASH_RE = re.compile(r"^-\s*$")
_KEY_VALUE_RE = re.compile(r"^([^\s:#][^:#]*?)\s*:\s*(.*)$")


def _strip_inline_comment(text: str) -> str:
    """Remove a ``#`` comment, respecting double / single quoted strings."""
    out = []
    in_s = False
    in_d = False
    for ch in text:
        if ch == "'" and not in_d:
            in_s = not in_s
            out.append(ch)
            continue
        if ch == '"' and not in_s:
            in_d = not in_d
            out.append(ch)
            continue
        if ch == "#" and not in_s and not in_d:
            break
        out.append(ch)
    return "".join(out).rstrip()


def _dequote(text: str) -> str:
    s = text.strip()
    if len(s) >= 2 and ((s[0] == '"' and s[-1] == '"')
                        or (s[0] == "'" and s[-1] == "'")):
        return s[1:-1]
    return s


def _indent_of(line: str) -> int:
    m = _INDENT_RE.match(line)
    return len(m.group(1)) if m else 0


@dataclass
class _Line:
    indent: int
    text: str      # content without leading whitespace, with inline comment stripped
    line: int      # 1-based physical line number


def _preprocess(content: str) -> List[_Line]:
    out: List[_Line] = []
    for i, physical in enumerate(content.splitlines(), start=1):
        # Preserve indent; strip inline comments; drop pure-comment /
        # blank lines.
        stripped_right = physical.rstrip()
        if not stripped_right.strip():
            continue
        if stripped_right.lstrip().startswith("#"):
            continue
        bare = _strip_inline_comment(stripped_right)
        if not bare.strip():
            continue
        indent = _indent_of(bare)
        out.append(_Line(indent=indent, text=bare[indent:], line=i))
    return out


def _parse_block(lines: List[_Line], start: int, indent: int
                 ) -> Tuple[int, Any]:
    """Parse a block starting at ``lines[start]`` whose contents are
    indented to exactly ``indent`` columns. Returns (next_index, value).
    """
    if start >= len(lines) or lines[start].indent < indent:
        return start, Scalar("", lines[start - 1].line if start else 0)
    first = lines[start]
    if first.text.startswith("- "):
        return _parse_sequence(lines, start, indent)
    if first.text == "-":
        return _parse_sequence(lines, start, indent)
    return _parse_mapping(lines, start, indent)


def _parse_mapping(lines: List[_Line], start: int, indent: int
                   ) -> Tuple[int, Dict[str, Any]]:
    out: Dict[str, Any] = {}
    i = start
    while i < len(lines):
        ln = lines[i]
        if ln.indent < indent:
            break
        if ln.indent > indent:
            # Should not happen if parsing is well-aligned; skip.
            i += 1
            continue
        m = _KEY_VALUE_RE.match(ln.text)
        if not m:
            # Not a key-value shape at this level; skip.
            i += 1
            continue
        key = m.group(1).strip()
        value_text = m.group(2).strip()
        if value_text == "":
            # Block value - look at next line's indent to decide if it
            # is a sequence or mapping.
            next_i = i + 1
            if next_i < len(lines) and lines[next_i].indent > indent:
                nested_indent = lines[next_i].indent
                next_i, value = _parse_block(lines, next_i, nested_indent)
                out[key] = value
                i = next_i
                continue
            else:
                # Empty block (common for secrets etc.) - represent as
                # empty mapping.
                out[key] = {}
                i += 1
                continue
        else:
            out[key] = Scalar(_dequote(value_text), ln.line)
            i += 1
            continue
    return i, out


def _parse_sequence(lines: List[_Line], start: int, indent: int
                    ) -> Tuple[int, List[Any]]:
    out: List[Any] = []
    i = start
    while i < len(lines):
        ln = lines[i]
        if ln.indent < indent:
            break
        if ln.indent > indent:
            i += 1
            continue
        if not (ln.text.startswith("- ") or ln.text == "-"):
            break
        if ln.text == "-":
            # Element body is on the next line(s), more-indented.
            next_i = i + 1
            if next_i < len(lines) and lines[next_i].indent > indent:
                nested_indent = lines[next_i].indent
                next_i, value = _parse_block(lines, next_i, nested_indent)
                out.append(value)
                i = next_i
                continue
            else:
                out.append(Scalar("", ln.line))
                i += 1
                continue
        body = ln.text[2:].strip()
        # ``- key: value`` with FOLLOWING deeper-indented lines is a
        # multi-line inline mapping (compose's long volume form). But
        # a lone ``- key: value`` with no continuation is almost always
        # a scalar in compose land (``- /var/run/docker.sock:/var/run
        # /docker.sock``, ``- no-new-privileges:true``,
        # ``- 8080:80``). Default to scalar unless we see continuation.
        m = _KEY_VALUE_RE.match(body)
        has_continuation = (
            i + 1 < len(lines)
            and lines[i + 1].indent > indent
        )
        if m and m.group(2).strip() != "" and has_continuation:
            # Multi-line inline mapping - first line opens the mapping,
            # follow-on lines at deeper indent extend it.
            key = m.group(1).strip()
            val = m.group(2).strip()
            inline = {key: Scalar(_dequote(val), ln.line)}
            next_i = i + 1
            nested_indent = lines[next_i].indent
            next_i, extra = _parse_mapping(lines, next_i, nested_indent)
            inline.update(extra)
            out.append(inline)
            i = next_i
            continue
        if m and m.group(2).strip() == "":
            # ``- key:`` with block body following
            key = m.group(1).strip()
            next_i = i + 1
            if next_i < len(lines) and lines[next_i].indent > indent:
                nested_indent = lines[next_i].indent
                next_i, value = _parse_block(lines, next_i, nested_indent)
                out.append({key: value})
                i = next_i
                continue
            out.append({key: {}})
            i += 1
            continue
        out.append(Scalar(_dequote(body), ln.line))
        i += 1
    return i, out


# ---------------------------------------------------------------------------
# Public surface
# ---------------------------------------------------------------------------

@dataclass
class ComposeTree:
    """Parsed compose file. The ``root`` dict is the top-level mapping;
    ``services`` is a convenience view onto its ``services:`` child.
    """
    root: Dict[str, Any] = field(default_factory=dict)
    services: List[Service] = field(default_factory=list)


def parse_compose(content: str) -> ComposeTree:
    lines = _preprocess(content)
    if not lines:
        return ComposeTree()
    _, root = _parse_mapping(lines, 0, 0)
    tree = ComposeTree(root=root)
    svc_block = root.get("services")
    if isinstance(svc_block, dict):
        for name, body in svc_block.items():
            # The service's starting line is the line of its first
            # child, or of its first scalar key. We approximate from the
            # body's first child line.
            start_line = 0
            if isinstance(body, dict):
                for v in body.values():
                    ln = _node_line(v)
                    if ln:
                        start_line = ln
                        break
            tree.services.append(Service(
                name=name,
                line=start_line,
                body=body if isinstance(body, dict) else {},
            ))
    return tree


def _node_line(node: Any) -> int:
    if isinstance(node, Scalar):
        return node.line
    if isinstance(node, dict):
        for v in node.values():
            ln = _node_line(v)
            if ln:
                return ln
    if isinstance(node, list):
        for v in node:
            ln = _node_line(v)
            if ln:
                return ln
    return 0


__all__ = [
    "ComposeTree",
    "Service",
    "Scalar",
    "parse_compose",
]
