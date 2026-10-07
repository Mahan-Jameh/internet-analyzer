"""
latency_test.py
================
Pings several well known targets and reports average latency, packet
loss and jitter (variation in RTT) for each - useful for spotting a
generally poor or unstable connection versus a specific block.
"""

from __future__ import annotations

import statistics
import time
from typing import Callable, Optional

from app.constants import LATENCY_PING_COUNT, LATENCY_TARGETS, PING_TIMEOUT
from app.logger import get_logger
from app.models import CheckResult, ModuleReport, Status
from app.utils.helpers import IS_WINDOWS, parse_ping_rtts, run_subprocess

log = get_logger(__name__)

ProgressCallback = Optional[Callable[[str], None]]


class LatencyTester:
    def __init__(self, targets: Optional[dict[str, str]] = None, progress_cb: ProgressCallback = None) -> None:
        self.targets = targets or LATENCY_TARGETS
        self.progress_cb = progress_cb

    def _report(self, message: str) -> None:
        if self.progress_cb:
            self.progress_cb(message)
        log.info(message)

    def _ping_target(self, name: str, host: str) -> CheckResult:
        self._report(f"Measuring latency to {name} ({host}) ...")
        start = time.perf_counter()

        if IS_WINDOWS:
            args = ["ping", "-n", str(LATENCY_PING_COUNT), "-w", str(int(PING_TIMEOUT * 1000)), host]
        else:
            args = ["ping", "-c", str(LATENCY_PING_COUNT), "-W", str(int(PING_TIMEOUT)), host]

        code, out, err = run_subprocess(args, timeout=PING_TIMEOUT * LATENCY_PING_COUNT + 5)
        duration_ms = (time.perf_counter() - start) * 1000.0

        rtts = parse_ping_rtts(out)
        loss_pct = 100.0 * (LATENCY_PING_COUNT - len(rtts)) / LATENCY_PING_COUNT

        details = {
            "target": host,
            "sent": LATENCY_PING_COUNT,
            "received": len(rtts),
            "loss_percent": round(loss_pct, 1),
            "rtts_ms": rtts,
        }

        if not rtts:
            return CheckResult(
                name=f"Latency to {name}",
                status=Status.FAILED,
                message="No replies received.",
                details=details,
                duration_ms=duration_ms,
            )

        avg = statistics.mean(rtts)
        jitter = statistics.pstdev(rtts) if len(rtts) > 1 else 0.0
        details["average_ms"] = round(avg, 1)
        details["jitter_ms"] = round(jitter, 1)

        if loss_pct > 0 or avg > 200:
            status = Status.WARNING
        else:
            status = Status.OK

        return CheckResult(
            name=f"Latency to {name}",
            status=status,
            message=f"Avg {avg:.1f} ms, jitter {jitter:.1f} ms, loss {loss_pct:.0f}%.",
            details=details,
            duration_ms=duration_ms,
        )

    def run_all(self) -> ModuleReport:
        report = ModuleReport(module_name="Latency Test")
        for name, host in self.targets.items():
            report.add(self._ping_target(name, host))
        report.finish()
        return report
