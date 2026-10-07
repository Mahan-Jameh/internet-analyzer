"""
retry.py
========
Selective retries with honest bookkeeping.

``run_with_retry`` runs one probe, retries *only* when the failure is of a kind
that can be transient, and reports what happened to the retry:

    first_attempt_ok       - worked immediately
    recovered_after_retry  - failed first, worked later (intermittent signal)
    persistent_failure     - failed on every attempt
    intermittent           - mixed results across several attempts
    not_retried            - failure that is deterministic, so no retry was made
"""

from __future__ import annotations

import threading
import time
from typing import Callable, TypeVar

from app.diag.results import RetryOutcome, TestResult
from app.diag.testconfig import RetryPolicy
from app.logger import get_logger

log = get_logger(__name__)
T = TypeVar("T", bound=TestResult)


class Cancelled(Exception):
    """Raised when cancellation was requested before a probe could start."""


def run_with_retry(
    probe: Callable[[int], T],
    policy: RetryPolicy,
    cancel: threading.Event | None = None,
    sleep: Callable[[float], None] = time.sleep,
) -> T:
    """
    ``probe(attempt_number)`` returns a TestResult. The returned result has
    ``attempts`` and ``retry_outcome`` filled in, and the history of earlier
    attempts is preserved in ``metadata['attempt_log']``.
    """
    attempt_log: list[dict[str, object]] = []
    result: T | None = None
    total = policy.max_retries + 1

    for attempt in range(1, total + 1):
        if cancel is not None and cancel.is_set():
            break
        result = probe(attempt)
        result.attempts = attempt
        attempt_log.append({
            "attempt": attempt, "status": result.status.value,
            "error_code": result.error_code, "duration_ms": result.duration_ms,
        })
        if result.ok or result.skipped:
            break
        if result.error_code not in policy.retry_on_codes:
            break                                    # deterministic: do not retry
        if attempt < total:
            sleep(policy.backoff_seconds)

    if result is None:
        raise Cancelled("cancelled before the first attempt")

    statuses_ok = [a["status"] in ("SUCCESS", "OPEN") for a in attempt_log]
    if len(attempt_log) == 1:
        outcome = RetryOutcome.FIRST_ATTEMPT_OK if result.ok else RetryOutcome.NOT_RETRIED
    elif result.ok and not statuses_ok[0]:
        outcome = RetryOutcome.RECOVERED_AFTER_RETRY
    elif any(statuses_ok) and not all(statuses_ok):
        outcome = RetryOutcome.INTERMITTENT
    else:
        outcome = RetryOutcome.PERSISTENT_FAILURE
    result.retry_outcome = outcome
    result.metadata["attempt_log"] = attempt_log
    if outcome is RetryOutcome.RECOVERED_AFTER_RETRY:
        result.warnings.append("Succeeded only after a retry - the path may be unreliable.")
    return result
