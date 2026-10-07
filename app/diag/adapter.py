"""
adapter.py
==========
Bridge between the detailed :class:`TestResult` and the legacy GUI/report types
(:class:`CheckResult`, :class:`ModuleReport`). The GUI keeps showing
OK / WARNING / FAILED; everything richer travels along in ``CheckResult.result``.
"""

from __future__ import annotations

from typing import Any, Iterable

from app.diag.results import TestResult, to_legacy_status
from app.models import CheckResult, ModuleReport


def check_from_result(name: str, result: TestResult, message: str | None = None,
                      details: dict[str, Any] | None = None) -> CheckResult:
    merged: dict[str, Any] = {
        "technical_status": result.status.value,
        "severity": result.severity.value if result.severity else None,
    }
    if result.interpretation:
        merged["interpretation"] = result.interpretation
    if result.confidence is not None:
        merged["confidence"] = result.confidence
    if result.error_code:
        merged["error_code"] = result.error_code
    merged.update(details or {})
    return CheckResult(
        name=name,
        status=to_legacy_status(result),
        message=message if message is not None else result.summary,
        details=merged,
        duration_ms=result.duration_ms,
        timestamp=result.started_at,
        result=result,
    )


def results_of(reports: Iterable[ModuleReport]) -> list[TestResult]:
    """All detailed results carried by a set of module reports."""
    out: list[TestResult] = []
    for m in reports:
        out += [c.result for c in m.checks if isinstance(c.result, TestResult)]
        out += [r for r in m.results if isinstance(r, TestResult)]
    return out
