"""
results.py
==========
The common, machine-readable result model.

``TechnicalStatus`` says *what was observed* on the wire. ``Severity`` says
*how much it matters to the user*. The two are deliberately independent:
a TCP ``TIMEOUT`` can be ``WARNING`` for an optional port and ``ERROR`` for
port 443 of a site the user asked about.

The old three-state GUI model (OK / WARNING / FAILED) is produced from these
by :func:`to_legacy_status` - it is only a presentation layer.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any

from app.models import Status


class TechnicalStatus(str, Enum):
    SUCCESS = "SUCCESS"
    OPEN = "OPEN"                        # TCP: connection established
    CLOSED = "CLOSED"                    # TCP: actively refused / UDP: ICMP port unreachable
    FILTERED = "FILTERED"                # strong evidence of filtering (rarely provable client-side)
    OPEN_OR_FILTERED = "OPEN_OR_FILTERED"  # UDP: silence - cannot tell
    TIMEOUT = "TIMEOUT"                  # no answer in time (NOT the same as CLOSED)
    UNREACHABLE = "UNREACHABLE"          # network/host unreachable (local stack or ICMP)
    REFUSED = "REFUSED"                  # DNS REFUSED, connection refused at app level
    RESET = "RESET"                      # connection reset after it started
    DNS_FAILED = "DNS_FAILED"
    TLS_FAILED = "TLS_FAILED"
    HTTP_FAILED = "HTTP_FAILED"
    BLOCKED = "BLOCKED"                  # explicit block page / 451 / policy response
    SKIPPED = "SKIPPED"                  # not run (dependency failed or not selected)
    NOT_APPLICABLE = "NOT_APPLICABLE"
    PARTIAL = "PARTIAL"                  # some sub-checks passed, some did not
    INCONCLUSIVE = "INCONCLUSIVE"        # a measurement was made but proves nothing
    ERROR = "ERROR"                      # local/internal error while testing
    UNKNOWN = "UNKNOWN"


class Severity(str, Enum):
    OK = "OK"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"
    SKIPPED = "SKIPPED"


class RetryOutcome(str, Enum):
    FIRST_ATTEMPT_OK = "first_attempt_ok"
    RECOVERED_AFTER_RETRY = "recovered_after_retry"
    PERSISTENT_FAILURE = "persistent_failure"
    INTERMITTENT = "intermittent"
    NOT_RETRIED = "not_retried"


class EvidenceKind(str, Enum):
    MEASURED = "measured"     # a fact that was observed
    INFERRED = "inferred"     # a conclusion drawn from facts


_SEVERITY_DEFAULT: dict[TechnicalStatus, Severity] = {
    TechnicalStatus.SUCCESS: Severity.OK,
    TechnicalStatus.OPEN: Severity.OK,
    TechnicalStatus.CLOSED: Severity.INFO,
    TechnicalStatus.FILTERED: Severity.WARNING,
    TechnicalStatus.OPEN_OR_FILTERED: Severity.INFO,
    TechnicalStatus.TIMEOUT: Severity.WARNING,
    TechnicalStatus.UNREACHABLE: Severity.ERROR,
    TechnicalStatus.REFUSED: Severity.WARNING,
    TechnicalStatus.RESET: Severity.ERROR,
    TechnicalStatus.DNS_FAILED: Severity.ERROR,
    TechnicalStatus.TLS_FAILED: Severity.ERROR,
    TechnicalStatus.HTTP_FAILED: Severity.ERROR,
    TechnicalStatus.BLOCKED: Severity.ERROR,
    TechnicalStatus.SKIPPED: Severity.SKIPPED,
    TechnicalStatus.NOT_APPLICABLE: Severity.SKIPPED,
    TechnicalStatus.PARTIAL: Severity.WARNING,
    TechnicalStatus.INCONCLUSIVE: Severity.INFO,
    TechnicalStatus.ERROR: Severity.ERROR,
    TechnicalStatus.UNKNOWN: Severity.INFO,
}


def default_severity(status: TechnicalStatus) -> Severity:
    return _SEVERITY_DEFAULT[status]


_GOOD = {TechnicalStatus.SUCCESS, TechnicalStatus.OPEN}


@dataclass
class Evidence:
    text: str
    kind: EvidenceKind = EvidenceKind.MEASURED
    source: str | None = None          # test_id the fact came from

    def to_dict(self) -> dict[str, Any]:
        return {"text": self.text, "kind": self.kind.value, "source": self.source}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Evidence":
        return cls(
            text=str(data.get("text", "")),
            kind=EvidenceKind(data.get("kind", "measured")),
            source=data.get("source"),
        )


@dataclass
class TestResult:
    """One normalized measurement. Never contains a bare boolean verdict."""

    __test__ = False  # not a pytest class

    test_id: str
    category: str                      # e.g. "tcp", "udp", "dns", "tls", "http", "icmp", ...
    status: TechnicalStatus = TechnicalStatus.UNKNOWN
    severity: Severity | None = None   # None -> derived from status
    target: str | None = None
    resolved_ip: str | None = None
    address_family: str | None = None  # "IPv4" / "IPv6"
    protocol: str | None = None        # "TCP", "UDP", "ICMP", "DNS", "TLS", "HTTP/2" ...
    port: int | None = None

    started_at: datetime = field(default_factory=datetime.now)
    duration_ms: float | None = None
    attempts: int = 1
    timeout_ms: int | None = None
    retry_outcome: RetryOutcome = RetryOutcome.NOT_RETRIED

    error_type: str | None = None
    error_code: str | None = None
    platform_error: int | None = None   # raw OS error number (errno / WSA code)
    error_message: str | None = None
    recoverable: bool | None = None

    interpretation: str | None = None   # e.g. "POSSIBLY_FILTERED"
    confidence: float | None = None     # 0..1, only for inferred statements
    summary: str = ""                   # one human line

    metrics: dict[str, Any] = field(default_factory=dict)
    evidence: list[Evidence] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    # ---- helpers --------------------------------------------------------
    def __setattr__(self, name: str, value: Any) -> None:
        # Severity follows the status until a module sets it explicitly. Without this,
        # a result created as UNKNOWN and later marked TIMEOUT would keep the old severity.
        object.__setattr__(self, name, value)
        if name == "severity":
            auto = value is None
            object.__setattr__(self, "_auto_severity", auto)
            if auto:
                object.__setattr__(self, "severity", default_severity(self.status))
        elif name == "status" and self.__dict__.get("_auto_severity", True):
            object.__setattr__(self, "severity", default_severity(value))

    @property
    def ok(self) -> bool:
        return self.status in _GOOD

    @property
    def skipped(self) -> bool:
        return self.status in (TechnicalStatus.SKIPPED, TechnicalStatus.NOT_APPLICABLE)

    def add_evidence(self, text: str, kind: EvidenceKind = EvidenceKind.MEASURED) -> None:
        self.evidence.append(Evidence(text, kind, self.test_id))

    def to_dict(self) -> dict[str, Any]:
        return {
            "test_id": self.test_id,
            "category": self.category,
            "status": self.status.value,
            "severity": self.severity.value if self.severity else None,
            "target": self.target,
            "resolved_ip": self.resolved_ip,
            "address_family": self.address_family,
            "protocol": self.protocol,
            "port": self.port,
            "started_at": self.started_at.isoformat(),
            "duration_ms": self.duration_ms,
            "attempts": self.attempts,
            "timeout_ms": self.timeout_ms,
            "retry_outcome": self.retry_outcome.value,
            "error_type": self.error_type,
            "error_code": self.error_code,
            "platform_error": self.platform_error,
            "error_message": self.error_message,
            "recoverable": self.recoverable,
            "interpretation": self.interpretation,
            "confidence": self.confidence,
            "summary": self.summary,
            "metrics": self.metrics,
            "evidence": [e.to_dict() for e in self.evidence],
            "warnings": self.warnings,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "TestResult":
        def _enum(enum_cls: Any, value: Any, default: Any) -> Any:
            try:
                return enum_cls(value)
            except ValueError:
                return default

        try:
            started = datetime.fromisoformat(data["started_at"])
        except (KeyError, TypeError, ValueError):
            started = datetime.now()
        status = _enum(TechnicalStatus, data.get("status"), TechnicalStatus.UNKNOWN)
        return cls(
            test_id=str(data.get("test_id", "unknown")),
            category=str(data.get("category", "unknown")),
            status=status,
            severity=_enum(Severity, data.get("severity"), None),
            target=data.get("target"),
            resolved_ip=data.get("resolved_ip"),
            address_family=data.get("address_family"),
            protocol=data.get("protocol"),
            port=data.get("port"),
            started_at=started,
            duration_ms=data.get("duration_ms"),
            attempts=int(data.get("attempts", 1) or 1),
            timeout_ms=data.get("timeout_ms"),
            retry_outcome=_enum(RetryOutcome, data.get("retry_outcome"), RetryOutcome.NOT_RETRIED),
            error_type=data.get("error_type"),
            error_code=data.get("error_code"),
            platform_error=data.get("platform_error"),
            error_message=data.get("error_message"),
            recoverable=data.get("recoverable"),
            interpretation=data.get("interpretation"),
            confidence=data.get("confidence"),
            summary=str(data.get("summary", "")),
            metrics=dict(data.get("metrics") or {}),
            evidence=[Evidence.from_dict(e) for e in data.get("evidence") or []],
            warnings=list(data.get("warnings") or []),
            metadata=dict(data.get("metadata") or {}),
        )


# --------------------------------------------------------------------------
# Presentation adapter: detailed result -> legacy GUI status
# --------------------------------------------------------------------------
def to_legacy_status(result: TestResult) -> Status:
    """Severity mapper. The GUI keeps showing OK / WARNING / FAILED."""
    sev = result.severity or default_severity(result.status)
    if sev in (Severity.OK, Severity.INFO):
        # An INFO-level "no verdict" (INCONCLUSIVE/UNKNOWN) is not a green tick.
        if result.status in (TechnicalStatus.INCONCLUSIVE, TechnicalStatus.UNKNOWN,
                             TechnicalStatus.OPEN_OR_FILTERED):
            return Status.UNKNOWN
        return Status.OK
    if sev == Severity.WARNING:
        return Status.WARNING
    if sev in (Severity.ERROR, Severity.CRITICAL):
        return Status.FAILED
    return Status.UNKNOWN          # SKIPPED
