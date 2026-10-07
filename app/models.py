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

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status.value,
            "message": self.message,
            "details": self.details,
            "duration_ms": self.duration_ms,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class ModuleReport:
    """The aggregated result of one full test module (e.g. 'DNS Test')."""

    module_name: str
    checks: list[CheckResult] = field(default_factory=list)
    started_at: datetime = field(default_factory=datetime.now)
    finished_at: datetime | None = None

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

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at.isoformat(),
            "profile_name": self.profile_name,
            "duration_seconds": self.duration_seconds,
            "cancelled": self.cancelled,
            "target_host": self.target_host,
            "network_info": self.network_info.to_dict(),
            "modules": [m.to_dict() for m in self.modules],
            "interpretations": [
                {"text": i.text, "severity": i.severity.value} for i in self.interpretations
            ],
        }
