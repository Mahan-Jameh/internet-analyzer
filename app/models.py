"""
models.py
=========
All shared dataclasses that flow between the ``core`` test modules, the
analysis engine, the GUI and the exporters. Keeping them in one place
means every layer of the app agrees on the exact same shape of data.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class Status(str, Enum):
    OK = "OK"
    WARNING = "WARNING"
    FAILED = "FAILED"
    UNKNOWN = "UNKNOWN"


@dataclass
class CheckResult:
    """The atomic result of a single, specific check (e.g. 'Ping 1.1.1.1')."""

    name: str
    status: Status
    message: str = ""
    details: dict[str, Any] = field(default_factory=dict)
    duration_ms: float | None = None
    timestamp: datetime = field(default_factory=datetime.now)
    # Detailed, machine-readable result (app.diag.results.TestResult) when the
    # producing module provides one. ``status`` above is then derived from it.
    result: Any | None = None

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "name": self.name,
            "status": self.status.value,
            "message": self.message,
            "details": self.details,
            "duration_ms": self.duration_ms,
            "timestamp": self.timestamp.isoformat(),
        }
        if self.result is not None:
            data["result"] = self.result.to_dict()
        return data


@dataclass
class ModuleReport:
    """The aggregated result of one full test module (e.g. 'DNS Test')."""

    module_name: str
    checks: list[CheckResult] = field(default_factory=list)
    started_at: datetime = field(default_factory=datetime.now)
    finished_at: datetime | None = None
    # Detailed results that do not belong to a single check card (e.g. one per
    # domain and resolver). They feed the correlation engine and the JSON report.
    results: list[Any] = field(default_factory=list)

    def add(self, check: CheckResult) -> None:
        self.checks.append(check)

    def finish(self) -> None:
        """Stamp the finish time (once)."""
        if self.finished_at is None:
            self.finished_at = datetime.now()

    @property
    def overall_status(self) -> Status:
        if not self.checks:
            return Status.UNKNOWN
        statuses = {c.status for c in self.checks}
        if Status.FAILED in statuses:
            return Status.FAILED
        if Status.WARNING in statuses:
            return Status.WARNING
        if statuses == {Status.UNKNOWN}:
            return Status.UNKNOWN
        return Status.OK

    def to_dict(self) -> dict[str, Any]:
        return {
            "module_name": self.module_name,
            "overall_status": self.overall_status.value,
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "checks": [c.to_dict() for c in self.checks],
            **({"results": [r.to_dict() for r in self.results]} if self.results else {}),
        }


@dataclass
class NetworkInfo:
    """Snapshot of the machine's current network environment for the home screen."""

    public_ip: str | None = None
    isp: str | None = None
    country: str | None = None
    city: str | None = None
    ipv4_available: bool = False
    ipv6_available: bool = False
    dns_servers: list[str] = field(default_factory=list)
    adapter_name: str | None = None
    gateway: str | None = None
    internet_reachable: bool = False
    # Layered detail (schema v2). The booleans above stay for compatibility.
    ipv4_state: str = "Unknown"          # Available / Not configured / Configured, no Internet access
    ipv6_state: str = "Unknown"
    public_ip_state: str = "NOT_TESTED"  # PUBLIC_IP_DETECTED / LOOKUP_FAILED / NOT_AVAILABLE / NOT_TESTED
    gateway_reachable: bool | None = None
    ip_layers: dict[str, Any] = field(default_factory=dict)   # {"ipv4": {...}, "ipv6": {...}}
    test_results: list[Any] = field(default_factory=list)     # TestResult objects (not serialized here)

    def to_dict(self) -> dict[str, Any]:
        return {
            "public_ip": self.public_ip,
            "isp": self.isp,
            "country": self.country,
            "city": self.city,
            "ipv4_available": self.ipv4_available,
            "ipv6_available": self.ipv6_available,
            "dns_servers": self.dns_servers,
            "adapter_name": self.adapter_name,
            "gateway": self.gateway,
            "internet_reachable": self.internet_reachable,
            "ipv4_state": self.ipv4_state,
            "ipv6_state": self.ipv6_state,
            "public_ip_state": self.public_ip_state,
            "gateway_reachable": self.gateway_reachable,
            "ip_layers": self.ip_layers,
        }


@dataclass
class Interpretation:
    """A single human readable, probabilistic interpretation line."""

    text: str
    severity: Status = Status.WARNING


@dataclass
class FullReport:
    """The complete result of a full diagnostic run - what gets exported."""

    network_info: NetworkInfo
    modules: list[ModuleReport] = field(default_factory=list)
    interpretations: list[Interpretation] = field(default_factory=list)
    generated_at: datetime = field(default_factory=datetime.now)
    profile_name: str | None = None
    duration_seconds: float | None = None
    cancelled: bool = False
    target_host: str | None = None
    # Correlation result (app.diag.correlation.DiagnosticSummary); None for old / hand-built reports.
    summary: Any | None = None

    def all_results(self) -> list[Any]:
        from app.diag.reportlayers import collect_results
        return collect_results(self.modules, self.network_info)

    def layers(self) -> dict[str, Any]:
        from app.diag.reportlayers import build_layers
        return build_layers(self.summary, self.all_results())

    def to_dict(self) -> dict[str, Any]:
        """
        History / JSON format, ``schema_version`` 2.

        The version-1 keys (``generated_at`` ... ``interpretations``) are kept at the top level so
        old readers keep working; the new keys are ``run``, ``tests``, ``diagnoses``, ``summary``
        and ``layers``. Readers must treat every new key as optional (see ``normalize_report_dict``).
        """
        from app.diag.reportlayers import SCHEMA_VERSION
        layers = self.layers()
        return {
            "schema_version": SCHEMA_VERSION,
            "run": {
                "generated_at": self.generated_at.isoformat(), "duration_seconds": self.duration_seconds,
                "cancelled": self.cancelled, "profile_name": self.profile_name,
                "target_host": self.target_host,
            },
            "generated_at": self.generated_at.isoformat(),
            "profile_name": self.profile_name,
            "duration_seconds": self.duration_seconds,
            "cancelled": self.cancelled,
            "target_host": self.target_host,
            "network_info": self.network_info.to_dict(),
            "summary": layers["overall_summary"],
            "diagnoses": layers["root_cause"],
            "key_findings": layers["key_findings"],
            "tests": [r.to_dict() for r in self.all_results()],
            "modules": [m.to_dict() for m in self.modules],
            "interpretations": [
                {"text": i.text, "severity": i.severity.value} for i in self.interpretations
            ],
        }
