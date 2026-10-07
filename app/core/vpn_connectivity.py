"""
vpn_connectivity.py
====================
Checks whether common VPN transport ports *appear* reachable from this
network, without ever connecting to any VPN service or claiming that a
VPN would actually work. This purely reports raw TCP/UDP reachability
of the transport ports typically used by VPN protocols.
"""

from __future__ import annotations

from typing import Callable, Optional

from app.constants import TCP_SCAN_TARGETS, VPN_TCP_PORTS, VPN_UDP_PORTS
from app.core.tcp_scanner import TCPScanner
from app.core.udp_test import UDPTester
from app.logger import get_logger
from app.models import CheckResult, ModuleReport, Status

log = get_logger(__name__)

ProgressCallback = Optional[Callable[[str], None]]

_DISCLAIMER = (
    "This only reports raw transport-level reachability of common VPN ports. "
    "It does NOT connect to any VPN and does NOT indicate whether a VPN service "
    "would actually function."
)


class VPNConnectivityTester:
    def __init__(self, progress_cb: ProgressCallback = None) -> None:
        self.progress_cb = progress_cb

    def _report(self, message: str) -> None:
        if self.progress_cb:
            self.progress_cb(message)
        log.info(message)

    def run_all(self) -> ModuleReport:
        report = ModuleReport(module_name="VPN-Related Connectivity")

        report.add(CheckResult(
            name="Scope Notice",
            status=Status.UNKNOWN,
            message=_DISCLAIMER,
        ))

        self._report("Checking common VPN TCP transport ports ...")
        tcp_target = TCP_SCAN_TARGETS["Cloudflare"]
        tcp_scanner = TCPScanner(target_host=tcp_target, ports=VPN_TCP_PORTS, progress_cb=self.progress_cb)
        for port in tcp_scanner.ports:
            probe = tcp_scanner.probe_port(port)
            status = Status.OK if probe.state == "open" else (
                Status.FAILED if probe.state == "reset" else Status.WARNING
            )
            report.add(CheckResult(
                name=f"VPN TCP {port} appears {probe.state}",
                status=status,
                message=f"Connectivity check only - target {tcp_target}:{port} -> {probe.state}.",
                details={"port": port, "target": tcp_target, "state": probe.state},
                duration_ms=probe.latency_ms,
            ))

        self._report("Checking common VPN UDP transport ports ...")
        udp_tester = UDPTester(ports=VPN_UDP_PORTS, progress_cb=self.progress_cb)
        for port in udp_tester.ports:
            check = udp_tester.probe_port(port)
            check.name = f"VPN UDP {port} connectivity"
            report.add(check)

        report.finish()
        return report
