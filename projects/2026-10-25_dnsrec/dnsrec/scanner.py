"""Scanner: open file(s), parse, run rules, roll up verdict."""

from __future__ import annotations

import os
from typing import Iterable

from .parse import parse_bare_text, parse_zone_text
from .rules import run_all
from .types import Finding, Options, RecordKind, ScanResult, Severity, Verdict
from .verdict import compute_verdict


def scan_text(content: str, path: str, options: Options) -> ScanResult:
    """Scan one text buffer. ``path`` is the display label."""
    if options.force_kind is not None:
        records = parse_bare_text(content, options.force_kind)
    else:
        records = parse_zone_text(content)
    findings = run_all(records, content, path, options)
    r = ScanResult(
        findings=findings,
        files_scanned=1,
        records_scanned=len(records),
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
                rule_id="DNSREC-000",
                severity=Severity.HIGH,
                message="cannot read file: " + str(e),
                owner="",
                line=0,
                path=path,
                hint="",
                citation="",
            )],
            files_scanned=0,
            records_scanned=0,
            verdict=Verdict.UNHEALTHY,
            error=str(e),
        )
    return scan_text(content, path, options)


def scan_paths(paths: Iterable[str], options: Options) -> ScanResult:
    """Scan every path, merging into one ScanResult."""
    merged = ScanResult()
    for p in paths:
        if os.path.isdir(p):
            # dnsrec does not auto-walk directories for zone files
            # (zone names are too varied to guess). Operators pass
            # explicit paths.
            merged.findings.append(Finding(
                rule_id="DNSREC-000",
                severity=Severity.HIGH,
                message="path is a directory; pass zone files explicitly",
                owner="",
                line=0,
                path=p,
                hint="",
                citation="",
            ))
            continue
        r = scan_file(p, options)
        merged.findings.extend(r.findings)
        merged.files_scanned += r.files_scanned
        merged.records_scanned += r.records_scanned
    merged.verdict = compute_verdict(
        merged.findings, merged.files_scanned, options,
    )
    merged.findings.sort(key=lambda f: (f.path, f.line, f.rule_id))
    return merged


__all__ = ["scan_text", "scan_file", "scan_paths"]
