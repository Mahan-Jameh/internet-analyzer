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
    def __init__(self, progress_cb: ProgressCallback = None) -> None:
        self.progress_cb = progress_cb

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
            return received, False, f"{exc.__class__.__name__}: {exc}"

    # ------------------------------------------------------------------ #
    def run_all(self) -> ModuleReport:
        report = ModuleReport(module_name="TCP Stall Test")
        report.add(self._run_check())
        report.finish()
        return report

    def _run_check(self) -> CheckResult:
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
