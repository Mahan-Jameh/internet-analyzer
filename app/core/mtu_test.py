"""
mtu_test.py
===========
Estimates the maximum usable MTU on the path to a target host using a
binary search over ICMP payload sizes sent with the "Don't Fragment"
flag set. If a payload size gets through undropped, the effective path
MTU is at least payload_size + 28 (20 byte IP header + 8 byte ICMP
header).
"""

from __future__ import annotations

import time
from typing import Callable, Optional

from app.constants import MTU_ETHERNET_OVERHEAD, MTU_MAX, MTU_MIN, MTU_TEST_HOST
from app.logger import get_logger
from app.models import CheckResult, ModuleReport, Status
from app.utils.helpers import IS_WINDOWS, parse_ping_rtts, run_subprocess

log = get_logger(__name__)

ProgressCallback = Optional[Callable[[str], None]]


class MTUTester:
    def __init__(self, host: str = MTU_TEST_HOST, progress_cb: ProgressCallback = None) -> None:
        self.host = host
        self.progress_cb = progress_cb

    def _report(self, message: str) -> None:
        if self.progress_cb:
            self.progress_cb(message)
        log.info(message)

    def _probe_payload_size(self, payload_size: int) -> bool:
        """Returns True if a DF-flagged ICMP packet of this payload size gets through."""
        if IS_WINDOWS:
            args = ["ping", "-n", "1", "-f", "-l", str(payload_size), "-w", "1500", self.host]
        else:
            args = ["ping", "-c", "1", "-M", "do", "-s", str(payload_size), "-W", "2", self.host]

        code, out, err = run_subprocess(args, timeout=5)
        # A real echo reply always carries a TTL value. Error replies such as
        # "Packet needs to be fragmented but DF set" never do, and this check
        # does not depend on the (possibly localized) wording of those errors.
        return len(parse_ping_rtts(out)) > 0

    def run_all(self) -> ModuleReport:
        report = ModuleReport(module_name="MTU Test")
        self._report(f"Discovering path MTU to {self.host} ...")
        start = time.perf_counter()

        low_payload = MTU_MIN - MTU_ETHERNET_OVERHEAD
        high_payload = MTU_MAX - MTU_ETHERNET_OVERHEAD

        # First confirm the lower bound actually works at all - if not, we
        # cannot reliably probe (host may block ICMP entirely).
        if not self._probe_payload_size(low_payload):
            duration_ms = (time.perf_counter() - start) * 1000.0
            report.add(CheckResult(
                name="Path MTU Discovery",
                status=Status.UNKNOWN,
                message=(
                    f"Could not get a baseline reply even at {MTU_MIN} bytes MTU - "
                    "ICMP may be blocked, so MTU could not be measured."
                ),
                duration_ms=duration_ms,
            ))
            report.finish()
            return report

        best_working_payload = low_payload
        lo, hi = low_payload, high_payload

        while lo <= hi:
            mid = (lo + hi) // 2
            if self._probe_payload_size(mid):
                best_working_payload = mid
                lo = mid + 1
            else:
                hi = mid - 1

        duration_ms = (time.perf_counter() - start) * 1000.0
        estimated_mtu = best_working_payload + MTU_ETHERNET_OVERHEAD

        if estimated_mtu >= 1500:
            status = Status.OK
            message = f"Estimated path MTU is {estimated_mtu} bytes (standard Ethernet MTU)."
        elif estimated_mtu >= 1400:
            status = Status.WARNING
            message = (
                f"Estimated path MTU is {estimated_mtu} bytes - slightly below the standard "
                "1500, which can happen with VPNs or tunnels but may also cause minor "
                "fragmentation issues."
            )
        else:
            status = Status.WARNING
            message = (
                f"Estimated path MTU is only {estimated_mtu} bytes - noticeably below standard, "
                "which can cause slow or failing connections for larger packets."
            )

        report.add(CheckResult(
            name="Path MTU Discovery",
            status=status,
            message=message,
            details={"estimated_mtu": estimated_mtu, "target": self.host},
            duration_ms=duration_ms,
        ))

        report.finish()
        return report
