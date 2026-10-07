"""
reportlayers.py
===============
The four-layer report. The same facts, shown at four depths so that a casual
reader and an engineer both get what they need:

    1. overall summary      one headline and a status
    2. key findings         a short list of ticks / warnings / crosses
    3. technical evidence   every measured result with its raw status and error codes
    4. root cause           the inferred diagnoses, each with confidence, evidence and caveats

Raw observation (layer 3) and interpretation (layer 4) are kept apart on purpose:
layer 3 never contains a conclusion, layer 4 always names the evidence it rests on.
"""

from __future__ import annotations

from typing import Any, Iterable

from app.diag.adapter import results_of
from app.diag.correlation import DiagnosticSummary
from app.diag.results import TestResult

SCHEMA_VERSION = 2


def collect_results(modules: Iterable[Any], network_info: Any | None = None) -> list[TestResult]:
    """All detailed results of a run, each exactly once, in report order."""
    seen: set[int] = set()
    out: list[TestResult] = []
    candidates = list(getattr(network_info, "test_results", []) or []) + results_of(modules)
    for r in candidates:
        if isinstance(r, TestResult) and id(r) not in seen:
            seen.add(id(r))
            out.append(r)
    return out


def evidence_row(r: TestResult) -> dict[str, Any]:
    """Layer 3 row: observation only."""
    return {
        "test_id": r.test_id, "category": r.category, "target": r.target, "resolved_ip": r.resolved_ip,
        "address_family": r.address_family, "protocol": r.protocol, "port": r.port,
        "status": r.status.value, "severity": r.severity.value if r.severity else None,
        "duration_ms": None if r.duration_ms is None else round(r.duration_ms, 1),
        "attempts": r.attempts, "retry_outcome": r.retry_outcome.value,
        "error_code": r.error_code, "platform_error": r.platform_error, "error_message": r.error_message,
        "interpretation": r.interpretation, "confidence": r.confidence, "summary": r.summary,
        "evidence": [e.text for e in r.evidence],
    }


def build_layers(summary: DiagnosticSummary | None, results: list[TestResult]) -> dict[str, Any]:
    layers: dict[str, Any] = {}
    if summary is None:
        layers["overall_summary"] = {"status": "INCONCLUSIVE", "headline": "No analysis available."}
        layers["key_findings"] = []
        layers["root_cause"] = []
    else:
        layers["overall_summary"] = {"status": summary.overall.value, "headline": summary.headline,
                                     "stats": summary.stats}
        layers["key_findings"] = [f.to_dict() for f in summary.findings]
        layers["root_cause"] = [d.to_dict() for d in summary.diagnoses]
        layers["blocked_tests"] = summary.blocked
    layers["technical_evidence"] = [evidence_row(r) for r in results]
    return layers
