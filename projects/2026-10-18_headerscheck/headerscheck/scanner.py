"""Scanner: open file(s), parse, run rules, roll up verdict."""

from __future__ import annotations

import os
from typing import Iterable

from .parse import load
from .rules import run_all
from .types import Finding, Options, ScanResult, Severity, Verdict
from .verdict import compute_verdict


def scan_text(content: str, path: str, options: Options) -> ScanResult:
    responses, err = load(content)
    if err is not None:
        return ScanResult(
            findings=[Finding(
                rule_id="HDR-000",
                severity=Severity.HIGH,
                message=err,
                header="",
                path=path,
                hint="file is not a parseable HTTP response or HAR entry",
                citation="",
            )],
            files_scanned=1,
            responses_scanned=0,
            verdict=Verdict.UNHEALTHY,
            error=err,
        )
    findings: list[Finding] = []
    for response in responses:
        findings.extend(run_all(response, path, options))
    r = ScanResult(
        findings=findings,
        files_scanned=1,
        responses_scanned=len(responses),
    )
    r.verdict = compute_verdict(findings, r.files_scanned, options)
    return r


def scan_file(path: str, options: Options) -> ScanResult:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
    except OSError as e:
        return ScanResult(
            findings=[Finding(
                rule_id="HDR-000",
                severity=Severity.HIGH,
                message="cannot read file: " + str(e),
                header="",
                path=path,
                hint="",
                citation="",
            )],
            files_scanned=0,
            responses_scanned=0,
            verdict=Verdict.UNHEALTHY,
            error=str(e),
        )
    return scan_text(content, path, options)


def scan_paths(paths: Iterable[str], options: Options) -> ScanResult:
    merged = ScanResult()
    for p in paths:
        if os.path.isdir(p):
            for root, _dirs, files in os.walk(p):
                for name in files:
                    if _plausible_filename(name):
                        full = os.path.join(root, name)
                        r = scan_file(full, options)
                        merged.findings.extend(r.findings)
                        merged.files_scanned += r.files_scanned
                        merged.responses_scanned += r.responses_scanned
        else:
            r = scan_file(p, options)
            merged.findings.extend(r.findings)
            merged.files_scanned += r.files_scanned
            merged.responses_scanned += r.responses_scanned
    merged.verdict = compute_verdict(
        merged.findings, merged.files_scanned, options
    )
    merged.findings.sort(key=lambda f: (f.path, f.rule_id))
    return merged


def _plausible_filename(name: str) -> bool:
    low = name.lower()
    return (
        low.endswith(".txt")
        or low.endswith(".http")
        or low.endswith(".headers")
        or low.endswith(".har")
        or low.endswith(".json")
        or "headers" in low
        or "response" in low
    )


__all__ = ["scan_text", "scan_file", "scan_paths"]
