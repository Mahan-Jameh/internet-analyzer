"""
structlog.py
============
Structured (key=value) log lines for every test result, one line per result:

    TEST RESULT test_id=tcp.example.com.443 category=tcp target=example.com ip=93.184.216.34 \
family=IPv4 protocol=TCP port=443 status=TIMEOUT severity=WARNING duration_ms=3004 attempts=2 \
retry=persistent_failure error_code=TIMEOUT os_error=10060 interp=POSSIBLY_FILTERED confidence=0.75

The same event is also attached to the log record (``record.event``), which the JSON-lines
handler in ``app.logger`` writes as one JSON object per line - so a run can be analysed with
ordinary tools (``grep``, ``jq``) without parsing prose.

Nothing sensitive is logged: no public IP, no response bodies, no headers, no credentials.
"""

from __future__ import annotations

import logging
from typing import Any

from app.diag.results import TestResult

_ORDER = ("test_id", "category", "target", "ip", "family", "protocol", "port", "status", "severity",
          "duration_ms", "attempts", "retry", "error_code", "os_error", "interp", "confidence")


def result_event(r: TestResult) -> dict[str, Any]:
    """The loggable facts of one result (observation only, no free text)."""
    return {
        "test_id": r.test_id, "category": r.category, "target": r.target, "ip": r.resolved_ip,
        "family": r.address_family, "protocol": r.protocol, "port": r.port, "status": r.status.value,
        "severity": r.severity.value if r.severity else None,
        "duration_ms": None if r.duration_ms is None else round(r.duration_ms),
        "attempts": r.attempts, "retry": r.retry_outcome.value, "error_code": r.error_code,
        "os_error": r.platform_error, "interp": r.interpretation, "confidence": r.confidence,
    }


def _fmt_value(value: Any) -> str:
    text = str(value)
    return f'"{text}"' if (" " in text or "=" in text or not text) else text


def format_event(event: dict[str, Any], prefix: str = "TEST RESULT") -> str:
    parts = [f"{k}={_fmt_value(event[k])}" for k in _ORDER if event.get(k) not in (None, "")]
    return f"{prefix} " + " ".join(parts)


def log_result(logger: logging.Logger, r: TestResult) -> None:
    """Log one result at a level that follows its severity. Never raises."""
    try:
        event = result_event(r)
        sev = event["severity"]
        level = (logging.ERROR if sev in ("ERROR", "CRITICAL")
                 else logging.WARNING if sev == "WARNING" else logging.INFO)
        logger.log(level, format_event(event), extra={"event": event})
    except Exception:  # noqa: BLE001 - logging must never break a test run
        logger.debug("could not log result %r", getattr(r, "test_id", "?"), exc_info=True)
