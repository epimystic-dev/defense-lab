"""Scanner: open file(s), parse, run rules, roll up verdict."""

from __future__ import annotations

import os
from typing import Iterable

from .parse import parse_text
from .rules import run_all
from .types import Finding, Options, ScanResult, Severity, Verdict
from .verdict import compute_verdict


# Filename shapes that are usually sshd_config files. Used when a user
# passes a directory - we only scan plausible candidates. A user can
# still pass any single file explicitly.
_SSHD_NAMES = ("sshd_config", "sshd.conf")


def _looks_like_sshd_config(name: str) -> bool:
    base = os.path.basename(name)
    if base in _SSHD_NAMES:
        return True
    if base.startswith("sshd_config"):
        return True
    if base.endswith(".conf") and "sshd" in base:
        return True
    return False


def scan_text(content: str, path: str, options: Options) -> ScanResult:
    """Scan one sshd_config string. ``path`` is the display label."""
    directives = parse_text(content)
    findings = run_all(directives, content, path, options)
    r = ScanResult(
        findings=findings,
        files_scanned=1,
        directives_scanned=len(directives),
    )
    r.verdict = compute_verdict(findings, r.files_scanned, options)
    return r


def scan_file(path: str, options: Options) -> ScanResult:
    """Scan one file. IO errors become a single HIGH finding so the
    verdict rollup stays uniform.
    """
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
    except OSError as e:
        return ScanResult(
            findings=[Finding(
                rule_id="SSH-000",
                severity=Severity.HIGH,
                message="cannot read file: " + str(e),
                directive="",
                line=0,
                path=path,
                hint="",
                citation="",
            )],
            files_scanned=0,
            directives_scanned=0,
            verdict=Verdict.UNHEALTHY,
            error=str(e),
        )
    return scan_text(content, path, options)


def scan_paths(paths: Iterable[str], options: Options) -> ScanResult:
    """Scan every path, merging into one ScanResult."""
    merged = ScanResult()
    for p in paths:
        if os.path.isdir(p):
            for root, _dirs, files in os.walk(p):
                for name in files:
                    full = os.path.join(root, name)
                    if _looks_like_sshd_config(full):
                        r = scan_file(full, options)
                        merged.findings.extend(r.findings)
                        merged.files_scanned += r.files_scanned
                        merged.directives_scanned += r.directives_scanned
        else:
            r = scan_file(p, options)
            merged.findings.extend(r.findings)
            merged.files_scanned += r.files_scanned
            merged.directives_scanned += r.directives_scanned
    merged.verdict = compute_verdict(
        merged.findings, merged.files_scanned, options
    )
    merged.findings.sort(key=lambda f: (f.path, f.line, f.rule_id))
    return merged


__all__ = ["scan_text", "scan_file", "scan_paths"]
