"""
tcp_stall_test.py
=================
Detects connections that start fine but are cut or frozen after a small
amount of data. Some filtering equipment behaves this way for traffic to
certain hosting/CDN providers (often reported at roughly 14-34 KB, hence
the common name "16-20 KB block").

Method: first prove the server is reachable with a tiny download, then
download a larger payload of known size and count the bytes that really
arrive on the wire. A failure after a small-but-nonzero number of bytes,
following a successful tiny request, matches the pattern.

The approach (a control request, then a bulk transfer observed for where
it dies) follows the methodology used by community DPI checkers such as
Runnin4ik/dpi-detector; this implementation is original.
"""

from __future__ import annotations

import threading
import time
from typing import Callable, Optional

import httpx

from app.constants import (
    TCP_STALL_SMALL_BYTES,
    TCP_STALL_SUSPECT_RANGE,
    TCP_STALL_TEST_BYTES,
    TCP_STALL_TIMEOUT,
    TCP_STALL_URL_TEMPLATE,
)
from app.diag.adapter import check_from_result
from app.diag.neterrors import normalize_wrapped_exception
from app.diag.results import Severity, TechnicalStatus, TestResult
from app.logger import get_logger
from app.models import CheckResult, ModuleReport, Status

log = get_logger(__name__)

ProgressCallback = Optional[Callable[[str], None]]


def classify_transfer(received: int, expected: int, completed: bool,
                      suspect_range: tuple[int, int] = TCP_STALL_SUSPECT_RANGE) -> str:
    """
    Pure classification used by the test (and unit tests):
    complete / stall_in_range / stall_early / stall_late
    """
    if completed and received >= expected:
        return "complete"
    low, high = suspect_range
    if received < low:
        return "stall_early"
    if received <= high:
        return "stall_in_range"
    return "stall_late"


class TCPStallTester:
    def __init__(self, progress_cb: ProgressCallback = None, cancel: Optional[threading.Event] = None) -> None:
        self.progress_cb = progress_cb
        self.cancel = cancel or threading.Event()

    def _report(self, message: str) -> None:
        if self.progress_cb:
            self.progress_cb(message)
        log.info(message)

    # ------------------------------------------------------------------ #
    def _download(self, size: int) -> tuple[int, bool, str]:
        """Download ``size`` bytes. Returns (wire_bytes_received, completed, error_text)."""
        url = TCP_STALL_URL_TEMPLATE.format(size=size)
        received = 0
        timeout = httpx.Timeout(TCP_STALL_TIMEOUT, connect=TCP_STALL_TIMEOUT)
        try:
            with httpx.Client(timeout=timeout, headers={"Accept-Encoding": "identity"}) as client:
                with client.stream("GET", url) as response:
                    if response.status_code >= 400:
                        return 0, False, f"HTTP {response.status_code}"
                    for chunk in response.iter_raw(chunk_size=1024):
                        received += len(chunk)
            return received, received >= size, ""
        except httpx.HTTPError as exc:
            self._last_error = normalize_wrapped_exception(exc)
            return received, False, f"{exc.__class__.__name__}: {exc}"

    # ------------------------------------------------------------------ #
    _last_error = None

    def run_all(self) -> ModuleReport:
        report = ModuleReport(module_name="TCP Stall Test")
        check = self._run_check()
        report.add(check)
        if isinstance(check.result, TestResult):
            report.results.append(check.result)
        report.finish()
        return report

    def _run_check(self) -> CheckResult:
        check = self._run_check_legacy()
        if check.result is not None:
            return check
        d, v = check.details, check.details.get("verdict")
        res = TestResult("tcp_stall", "tcp_stall", protocol="TCP", port=443, duration_ms=check.duration_ms,
                         metrics={k: d.get(k) for k in ("expected_bytes", "received_bytes", "verdict")},
                         metadata={"role": "stall", "control_ok": d.get("control_ok")}, summary=check.message)
        err = self._last_error
        if err is not None:
            res.error_code, res.error_type, res.error_message = err.error_code, err.error_type, err.error_message
        S = TechnicalStatus
        if not d.get("control_ok"):
            res.status, res.severity = S.INCONCLUSIVE, Severity.INFO     # nothing to compare against
        elif v == "complete":
            res.status = S.SUCCESS
        elif v == "stall_in_range":
            res.status, res.interpretation, res.confidence = S.RESET if "Reset" in (d.get("error") or "") else S.PARTIAL, "STALL_IN_SUSPECT_RANGE", 0.6
            res.severity = Severity.WARNING
        elif v == "stall_early":
            res.status, res.severity, res.interpretation, res.confidence = S.PARTIAL, Severity.ERROR, "EARLY_TRANSFER_FAILURE", 0.4
        else:
            res.status, res.severity, res.interpretation, res.confidence = S.PARTIAL, Severity.WARNING, "GENERAL_TRANSFER_PROBLEM", 0.4
        res.add_evidence(f"Control request {'worked' if d.get('control_ok') else 'failed'}; "
                         f"{d.get('received_bytes', 0)} of {d.get('expected_bytes', 0)} bytes received")
        return check_from_result(check.name, res, message=check.message, details=d)

    def _run_check_legacy(self) -> CheckResult:
        name = "TCP Stall (16-20 KB) Test"
        start = time.perf_counter()

        self._report("Control request for the TCP stall test ...")
        small_received, small_ok, small_err = self._download(TCP_STALL_SMALL_BYTES)
        if not small_ok:
            return CheckResult(
                name=name,
                status=Status.UNKNOWN,
                message=(
                    "The test server could not be reached with a tiny request, so the result "
                    f"would be meaningless ({small_err or 'incomplete response'})."
                ),
                details={"control_ok": False, "error": small_err},
                duration_ms=(time.perf_counter() - start) * 1000.0,
            )

        self._report(f"Downloading {TCP_STALL_TEST_BYTES // 1024} KB to look for stalls ...")
        received, completed, error = self._download(TCP_STALL_TEST_BYTES)
        duration_ms = (time.perf_counter() - start) * 1000.0
        verdict = classify_transfer(received, TCP_STALL_TEST_BYTES, completed)
        details = {
            "control_ok": True,
            "expected_bytes": TCP_STALL_TEST_BYTES,
            "received_bytes": received,
            "verdict": verdict,
            "error": error,
            "suspected": verdict == "stall_in_range",
        }

        if verdict == "complete":
            return CheckResult(
                name=name, status=Status.OK,
                message=f"All {received // 1024} KB arrived; no stall pattern observed.",
                details=details, duration_ms=duration_ms,
            )
        if verdict == "stall_in_range":
            return CheckResult(
                name=name, status=Status.WARNING,
                message=(
                    f"The tiny request worked, but the transfer died after about "
                    f"{received / 1024:.1f} KB ({error or 'stalled'}). That matches the "
                    "'16-20 KB' pattern reported for some filtering systems, though a flaky "
                    "connection could produce the same symptom."
                ),
                details=details, duration_ms=duration_ms,
            )
        if verdict == "stall_early":
            return CheckResult(
                name=name, status=Status.FAILED,
                message=(
                    f"The transfer failed almost immediately ({received} bytes, "
                    f"{error or 'stalled'}) although the tiny request worked."
                ),
                details=details, duration_ms=duration_ms,
            )
        return CheckResult(
            name=name, status=Status.WARNING,
            message=(
                f"The transfer was interrupted after {received / 1024:.1f} KB of "
                f"{TCP_STALL_TEST_BYTES // 1024} KB ({error or 'stalled'}). This is outside the "
                "typical filtering range and more likely a general connection problem."
            ),
            details=details, duration_ms=duration_ms,
        )
