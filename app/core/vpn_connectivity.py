"""
vpn_connectivity.py
====================
Reports raw reachability of the transport ports commonly used by VPN protocols,
without ever connecting to a VPN or claiming that one would work.

A port that does not respond is *not* evidence that a VPN is blocked: UDP silence
is inconclusive by nature, and the targets here are ordinary public hosts that
run no VPN service. The summary therefore lists what was observed per port and
a cautious reading with an explicit confidence - never a verdict.
"""

from __future__ import annotations

import threading
from typing import Callable, Optional

from app.constants import TCP_SCAN_TARGETS, VPN_TCP_PORTS, VPN_UDP_PORTS
from app.core.tcp_scanner import TCPScanner
from app.core.udp_test import UDPTester
from app.diag.adapter import check_from_result
from app.diag.results import Severity, TechnicalStatus, TestResult
from app.diag.testconfig import DEFAULT_CONFIG, NetworkTestConfig
from app.logger import get_logger
from app.models import CheckResult, ModuleReport, Status

log = get_logger(__name__)
_S = TechnicalStatus

ProgressCallback = Optional[Callable[[str], None]]

_DISCLAIMER = (
    "This only reports raw transport-level reachability of common VPN ports. "
    "It does NOT connect to any VPN and does NOT indicate whether a VPN service "
    "would actually function."
)


def summarize(tcp: list[TestResult], udp: list[TestResult]) -> TestResult:
    """Evidence-based reading of the per-port observations (kept separate from the observations)."""
    parts = [f"TCP {r.port}: {r.status.value}" for r in tcp] + [f"UDP {r.port}: {r.status.value}" for r in udp]
    res = TestResult("vpn_ports.summary", "vpn_ports", severity=Severity.INFO, status=_S.INCONCLUSIVE,
                     metrics={"tcp": {str(r.port): r.status.value for r in tcp},
                              "udp": {str(r.port): r.status.value for r in udp}})
    tcp_open = [r for r in tcp if r.status is _S.OPEN]
    udp_open = [r for r in udp if r.status is _S.OPEN]
    udp_silent = [r for r in udp if r.status in (_S.INCONCLUSIVE, _S.OPEN_OR_FILTERED, _S.TIMEOUT)]
    for part in parts:
        res.add_evidence(part)
    if tcp_open:
        res.add_evidence(f"{len(tcp_open)} TCP transport port(s) reachable; TCP-based tunnels are not generally blocked.")
    if udp_silent:
        res.add_evidence(f"{len(udp_silent)} UDP port(s) gave no answer; with no VPN server there this is expected.")
    if tcp_open or udp_open:
        res.interpretation, res.confidence = "SOME_TRANSPORTS_REACHABLE", 0.6
        res.summary = ("Some VPN transport ports are reachable. This says nothing about whether a specific "
                       "VPN service works.")
    else:
        res.interpretation, res.confidence = "NO_CONCLUSION", 0.2
        res.summary = ("No VPN transport port answered. That is not enough to conclude that VPNs are blocked: "
                       "silence has several ordinary explanations.")
    return res


class VPNConnectivityTester:
    def __init__(self, progress_cb: ProgressCallback = None, config: NetworkTestConfig = DEFAULT_CONFIG,
                 cancel: Optional[threading.Event] = None) -> None:
        self.progress_cb = progress_cb
        self.config = config
        self.cancel = cancel or threading.Event()

    def _report(self, message: str) -> None:
        if self.progress_cb:
            self.progress_cb(message)
        log.info(message)

    def run_all(self) -> ModuleReport:
        report = ModuleReport(module_name="VPN-Related Connectivity")
        report.add(CheckResult(name="Scope Notice", status=Status.UNKNOWN, message=_DISCLAIMER))

        self._report("Checking common VPN TCP transport ports ...")
        tcp_target = TCP_SCAN_TARGETS["Cloudflare"]
        scanner = TCPScanner(target_host=tcp_target, ports=VPN_TCP_PORTS, progress_cb=self.progress_cb,
                             config=self.config, cancel=self.cancel)
        tcp_results = [r for r in scanner.scan() if r.category == "tcp"]
        for res in tcp_results:
            state = res.status.value.lower()
            report.add(check_from_result(
                f"VPN TCP {res.port} appears {state}", res,
                message=f"Connectivity check only - target {tcp_target}:{res.port} -> {state}.",
                details={"port": res.port, "target": tcp_target, "state": state}))

        self._report("Checking common VPN UDP transport ports ...")
        udp = UDPTester(ports=VPN_UDP_PORTS, progress_cb=self.progress_cb, config=self.config, cancel=self.cancel)
        udp_results: list[TestResult] = []
        for port in udp.ports:
            if self.cancel.is_set():
                break
            res = udp.probe_port(port)
            if res.category == "udp":
                udp_results.append(res)
            report.add(check_from_result(f"VPN UDP {port} connectivity", res,
                                         details={"port": port, "target": res.resolved_ip or res.target}))

        report.add(check_from_result("Reading of the results", summarize(tcp_results, udp_results)))
        report.finish()
        return report
