"""Scanner: open file(s), classify, parse, run rules, roll up verdict."""

from __future__ import annotations

import os
from typing import Iterable, Optional

from .parse_compose import ComposeTree, parse_compose
from .parse_dockerfile import Instruction, parse_dockerfile
from .rules import run_all
from .types import FileKind, Finding, Options, ScanResult, Severity, Verdict
from .verdict import compute_verdict


_DOCKERFILE_NAMES = {"dockerfile", "containerfile"}
_COMPOSE_NAMES = {
    "docker-compose.yml", "docker-compose.yaml",
    "compose.yml", "compose.yaml",
}


def classify_filename(path: str) -> FileKind:
    base = os.path.basename(path).lower()
    if base in _DOCKERFILE_NAMES:
        return FileKind.DOCKERFILE
    if base in _COMPOSE_NAMES:
        return FileKind.COMPOSE
    # Common variants
    if base.startswith("dockerfile.") or base.endswith(".dockerfile"):
        return FileKind.DOCKERFILE
    if base.startswith("docker-compose.") or base.endswith(".compose.yml") \
            or base.endswith(".compose.yaml"):
        return FileKind.COMPOSE
    return FileKind.UNKNOWN


def classify_content(content: str) -> FileKind:
    for raw in content.splitlines():
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        up = s.split(None, 1)[0].upper()
        if up == "FROM":
            return FileKind.DOCKERFILE
        if up in ("ARG", "RUN", "COPY", "ADD", "ENV", "USER",
                  "WORKDIR", "LABEL"):
            return FileKind.DOCKERFILE
        if s.startswith("services:") or s == "services:" \
                or s.startswith("version:"):
            return FileKind.COMPOSE
        break
    # Fall back on scanning: if we see 'services:' at column 0 anywhere,
    # treat it as compose.
    for raw in content.splitlines():
        if raw.strip().lower() == "services:":
            return FileKind.COMPOSE
    return FileKind.UNKNOWN


def scan_text(content: str, path: str, options: Options,
              kind: Optional[FileKind] = None) -> ScanResult:
    """Scan one text buffer. ``path`` is the display label."""
    k = kind if kind is not None else classify_filename(path)
    if k is FileKind.UNKNOWN:
        k = classify_content(content)
    instructions: list = []
    compose: Optional[ComposeTree] = None
    if k is FileKind.DOCKERFILE:
        instructions = parse_dockerfile(content)
    elif k is FileKind.COMPOSE:
        compose = parse_compose(content)
    else:
        return ScanResult(
            findings=[Finding(
                rule_id="COMPOSE-000",
                severity=Severity.HIGH,
                message=(
                    "cannot classify as Dockerfile or docker-compose: "
                    + path
                ),
                subject="",
                line=0,
                path=path,
                hint="Rename the file to Dockerfile / docker-compose.yml or pass --as dockerfile|compose.",
                citation="",
            )],
            files_scanned=0,
            instructions_scanned=0,
            verdict=Verdict.UNHEALTHY,
            error="unknown file kind",
        )
    findings = run_all(instructions, compose, path, options)
    n_instr = len(instructions) if instructions else (
        len(compose.services) if compose is not None else 0)
    r = ScanResult(
        findings=findings,
        files_scanned=1,
        instructions_scanned=n_instr,
    )
    r.verdict = compute_verdict(findings, r.files_scanned, options)
    return r


def scan_file(path: str, options: Options,
              kind: Optional[FileKind] = None) -> ScanResult:
    """Scan one file. IO errors become a single HIGH finding."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
    except OSError as e:
        return ScanResult(
            findings=[Finding(
                rule_id="COMPOSE-000",
                severity=Severity.HIGH,
                message="cannot read file: " + str(e),
                subject="",
                line=0,
                path=path,
                hint="",
                citation="",
            )],
            files_scanned=0,
            instructions_scanned=0,
            verdict=Verdict.UNHEALTHY,
            error=str(e),
        )
    return scan_text(content, path, options, kind)


def scan_paths(paths: Iterable[str], options: Options,
               kind: Optional[FileKind] = None) -> ScanResult:
    """Scan every path, merging into one ScanResult."""
    merged = ScanResult()
    for p in paths:
        if os.path.isdir(p):
            for root, _dirs, files in os.walk(p):
                for name in files:
                    full = os.path.join(root, name)
                    k = classify_filename(full)
                    if k is FileKind.UNKNOWN:
                        continue
                    r = scan_file(full, options, k)
                    merged.findings.extend(r.findings)
                    merged.files_scanned += r.files_scanned
                    merged.instructions_scanned += r.instructions_scanned
            continue
        r = scan_file(p, options, kind)
        merged.findings.extend(r.findings)
        merged.files_scanned += r.files_scanned
        merged.instructions_scanned += r.instructions_scanned
    merged.verdict = compute_verdict(
        merged.findings, merged.files_scanned, options,
    )
    merged.findings.sort(key=lambda f: (f.path, f.line, f.rule_id))
    return merged


__all__ = [
    "classify_filename",
    "classify_content",
    "scan_text",
    "scan_file",
    "scan_paths",
]
