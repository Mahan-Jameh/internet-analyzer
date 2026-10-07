"""
mtu_test.py
===========
Estimates the usable path MTU towards a target with a binary search over ICMP
payload sizes sent with the Don't-Fragment flag (IPv4). If a payload of N bytes
gets through, the path MTU is at least N + 28 (20 byte IP + 8 byte ICMP header).

The report keeps the measurements separate from the interpretation:
``interface_mtu``, ``discovered_path_mtu``, ``largest_successful_packet``,
``smallest_failed_packet`` / ``largest_failed_packet`` and ``pmtud_status``.
A reduced MTU is described with possible causes, never with a single "root cause".
"""

from __future__ import annotations

import re
import threading
import time
from typing import Callable, Optional

from app.constants import MTU_ETHERNET_OVERHEAD, MTU_MAX, MTU_MIN, MTU_TEST_HOST
from app.core.icmp import run_ping
from app.diag.adapter import check_from_result
from app.diag.results import Severity, TechnicalStatus, TestResult
from app.diag.testconfig import DEFAULT_CONFIG, NetworkTestConfig
from app.logger import get_logger
from app.models import ModuleReport
from app.utils.helpers import IS_WINDOWS, run_subprocess

log = get_logger(__name__)
_S = TechnicalStatus

ProgressCallback = Optional[Callable[[str], None]]
PROBE_TIMEOUT_S = 1.5

_NETSH_ROW = re.compile(r"^\s*(\d+)\s+\d+\s+\d+\s+\d+\s+(.+?)\s*$", re.MULTILINE)


def parse_netsh_mtus(text: str) -> dict[str, int]:
    """``netsh interface ipv4 show subinterfaces`` rows: MTU first, interface name last."""
    return {m.group(2): int(m.group(1)) for m in _NETSH_ROW.finditer(text) if int(m.group(1)) < 100000}


def interface_mtu(adapter_name: str | None = None) -> int | None:
    """MTU of the active interface when it can be determined, else None."""
    try:
        if IS_WINDOWS:
            code, out, _ = run_subprocess(["netsh", "interface", "ipv4", "show", "subinterfaces"], timeout=6.0)
            table = parse_netsh_mtus(out) if code == 0 else {}
            if adapter_name and adapter_name in table:
                return table[adapter_name]
            return None
        from app.diag.localnet import default_routes
        for route in default_routes("IPv4"):
            if route.interface:
                with open(f"/sys/class/net/{route.interface}/mtu", encoding="utf-8") as fh:
                    return int(fh.read().strip())
    except (OSError, ValueError):
        return None
    return None


class MTUTester:
    def __init__(self, host: str = MTU_TEST_HOST, progress_cb: ProgressCallback = None,
                 config: NetworkTestConfig = DEFAULT_CONFIG, cancel: Optional[threading.Event] = None,
                 adapter_name: str | None = None, runner=run_ping) -> None:  # noqa: ANN001
        self.host = host
        self.progress_cb = progress_cb
        self.config = config
        self.cancel = cancel or threading.Event()
        self.adapter_name = adapter_name
        self._run = runner

    def _report(self, message: str) -> None:
        if self.progress_cb:
            self.progress_cb(message)
        log.info(message)

    def _probe(self, payload_size: int):  # noqa: ANN202
        """A DF-flagged echo. Success = a real reply (it carries ``TTL=``); wording of errors is not parsed."""
        out = self._run(self.host, 1, PROBE_TIMEOUT_S, df_size=payload_size)
        return out.received > 0, out

    def measure(self) -> TestResult:
        self._report(f"Discovering path MTU to {self.host} ...")
        start = time.perf_counter()
        res = TestResult(f"mtu.{self.host}", "mtu", target=self.host, protocol="ICMP/IPv4 (DF set)",
                         metrics={"interface_mtu": interface_mtu(self.adapter_name), "discovered_path_mtu": None,
                                  "largest_successful_packet": None, "largest_failed_packet": None,
                                  "smallest_failed_packet": None, "pmtud_status": "unknown"})

        low, high = MTU_MIN - MTU_ETHERNET_OVERHEAD, MTU_MAX - MTU_ETHERNET_OVERHEAD
        ok, out = self._probe(low)
        if not ok:
            res.status, res.severity = _S.INCONCLUSIVE, Severity.INFO
            res.interpretation = "ICMP_BLOCKED_OR_UNAVAILABLE"
            res.summary = (f"No reply even at {MTU_MIN} bytes, so the path MTU could not be measured "
                           "(ICMP may be blocked on this path).")
            res.duration_ms = (time.perf_counter() - start) * 1000.0
            return res

        best, lo, hi = low, low, high
        while lo <= hi and not self.cancel.is_set():
            mid = (lo + hi) // 2
            if self._probe(mid)[0]:
                best, lo = mid, mid + 1
            else:
                hi = mid - 1
        # the binary search leaves best+1 as the first size that failed (if any size failed)
        smallest_fail = best + 1 if best < high else None
        mtu = best + MTU_ETHERNET_OVERHEAD
        m = res.metrics
        m.update(discovered_path_mtu=mtu, largest_successful_packet=mtu,
                 smallest_failed_packet=(smallest_fail + MTU_ETHERNET_OVERHEAD) if smallest_fail else None,
                 largest_failed_packet=(high + MTU_ETHERNET_OVERHEAD) if smallest_fail else None)

        if smallest_fail is None:
            m["pmtud_status"] = "not_needed"
        else:
            _ok, fail_out = self._probe(smallest_fail)
            # A router that answers "fragmentation needed" proves PMTUD signalling works.
            m["pmtud_status"] = "working" if fail_out.reporter_ip else "no_icmp_feedback"
            if fail_out.reporter_ip:
                res.add_evidence(f"{fail_out.reporter_ip} reported that the oversized packet needs fragmentation.")

        iface = m["interface_mtu"]
        res.add_evidence(f"Largest DF packet that passed: {mtu} bytes.")
        if iface and mtu < iface:
            res.add_evidence(f"The interface MTU is {iface}, the path MTU {mtu}: a device on the path limits packet size.")
        res.duration_ms = (time.perf_counter() - start) * 1000.0

        if mtu >= MTU_MAX:
            res.status, res.severity = _S.SUCCESS, Severity.OK
            res.summary = f"Path MTU is {mtu} bytes (standard Ethernet)."
        else:
            res.status = _S.PARTIAL
            res.severity = Severity.INFO if mtu >= 1400 else Severity.WARNING
            res.interpretation = "REDUCED_PATH_MTU"
            res.confidence = 0.45
            res.summary = (f"Path MTU is {mtu} bytes, below the standard {MTU_MAX}. Possible PPPoE/VPN/"
                           "encapsulation overhead or a PMTUD problem; this alone does not identify a cause.")
            if m["pmtud_status"] == "no_icmp_feedback":
                res.warnings.append("Oversized packets were dropped silently (no ICMP feedback): "
                                    "large transfers may stall if ICMP is filtered somewhere on the path.")
        return res

    def run_all(self) -> ModuleReport:
        report = ModuleReport(module_name="MTU Test")
        try:
            res = self.measure()
        except Exception as exc:  # noqa: BLE001
            log.exception("MTU measurement crashed")
            res = TestResult(f"mtu.{self.host}", "mtu", status=_S.ERROR, target=self.host,
                             error_type=type(exc).__name__, error_message=str(exc)[:200],
                             summary="The MTU could not be measured (internal error).")
        details = {"estimated_mtu": res.metrics.get("discovered_path_mtu"), "target": self.host,
                   **{k: v for k, v in res.metrics.items() if k != "discovered_path_mtu"}}
        report.add(check_from_result("Path MTU Discovery", res, details=details))
        report.finish()
        return report
