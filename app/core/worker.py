"""
worker.py
=========
A QThread-based worker that runs the selected diagnostic modules off the
GUI thread, emitting progress and per-module signals so the UI can update
live and never freezes during long-running network tests.

Guarantees:
  * "network_info" always runs first (the analyzer needs it).
  * one failing module never stops the others - it becomes an UNKNOWN result.
  * the run can be cancelled between modules (``requestInterruption``).
  * every run is summarised in the log: timestamp, duration, errors, network info.
"""

from __future__ import annotations

import time
from datetime import datetime
from typing import Callable, Optional

from PySide6.QtCore import QThread, Signal

from app.constants import LATENCY_TARGETS
from app.core.analyzer import ResultAnalyzer
from app.core.basic_connectivity import BasicConnectivityTester
from app.core.dns_test import DNSTester
from app.core.environment_check import EnvironmentChecker
from app.core.http_test import HTTPTester
from app.core.latency_test import LatencyTester
from app.core.mtu_test import MTUTester
from app.core.network_info import NetworkInfoCollector
from app.core.protocol_tests import ProtocolTester
from app.core.protocol_whitelist import ProtocolWhitelistProbe
from app.core.site_reachability import SiteReachabilityTester
from app.core.tcp_scanner import TCPScanner
from app.core.tcp_stall_test import TCPStallTester
from app.core.tls_test import TLSTester
from app.core.udp_test import UDPTester
from app.core.vpn_connectivity import VPNConnectivityTester
from app.logger import get_logger
from app.models import CheckResult, FullReport, ModuleReport, NetworkInfo, Status
from app.utils.helpers import validate_target_host

log = get_logger(__name__)

# The canonical, ordered list of every module the app can run.
ALL_MODULES = [
    "network_info",
    "environment_check",
    "basic_connectivity",
    "dns_test",
    "tcp_scanner",
    "udp_test",
    "tls_test",
    "http_test",
    "tcp_stall",
    "site_reachability",
    "protocol_tests",
    "latency_test",
    "mtu_test",
    "vpn_connectivity",
    "protocol_whitelist",
]

# Modules that are NOT part of a default run. The protocol whitelist probe
# can interrupt the connection for a while, so the user must opt in.
OPT_IN_MODULES = {"protocol_whitelist"}
DEFAULT_MODULES = [m for m in ALL_MODULES if m not in OPT_IN_MODULES]

# Shown by the GUI. The report of each module uses exactly the same name.
MODULE_DISPLAY_NAMES = {
    "network_info": "Network Information",
    "environment_check": "Proxy & VPN Detection",
    "basic_connectivity": "Basic Connectivity",
    "dns_test": "DNS Test",
    "tcp_scanner": "TCP Port Scanner",
    "udp_test": "UDP Test",
    "tls_test": "TLS Test",
    "http_test": "HTTP Test",
    "tcp_stall": "TCP Stall Test",
    "site_reachability": "Website Reachability",
    "protocol_tests": "Protocol Tests",
    "latency_test": "Latency Test",
    "mtu_test": "MTU Test",
    "vpn_connectivity": "VPN-Related Connectivity",
    "protocol_whitelist": "Protocol Whitelist Probe",
}


def normalize_modules(requested: Optional[list[str]]) -> list[str]:
    """Keep only known modules, in canonical order, with network_info always first."""
    wanted = set(requested) if requested else set(DEFAULT_MODULES)
    wanted.add("network_info")
    return [m for m in ALL_MODULES if m in wanted]


class DiagnosticWorker(QThread):
    """Runs the requested test modules sequentially on a background thread."""

    progress_message = Signal(str)
    module_started = Signal(str)
    module_finished = Signal(object)      # emits a ModuleReport
    network_info_ready = Signal(object)   # emits a NetworkInfo
    run_finished = Signal(object)         # emits the final FullReport
    run_failed = Signal(str)

    def __init__(
        self,
        modules_to_run: Optional[list[str]] = None,
        target_host: Optional[str] = None,
        tcp_ports: Optional[list[int]] = None,
        udp_ports: Optional[list[int]] = None,
        test_sites: Optional[list[str]] = None,
        profile_name: Optional[str] = None,
        parent=None,
    ) -> None:
        super().__init__(parent)
        self.modules_to_run = normalize_modules(modules_to_run)
        self.target_host = validate_target_host(target_host)
        if target_host and self.target_host is None:
            log.warning("Ignoring invalid target host: %r", target_host)
        self.tcp_ports = tcp_ports
        self.udp_ports = udp_ports
        self.test_sites = test_sites
        self.profile_name = profile_name
        self._network_info: NetworkInfo = NetworkInfo()
        self._module_reports: list[ModuleReport] = []

    # ------------------------------------------------------------------ #
    def run(self) -> None:
        started_wall = datetime.now()
        started = time.perf_counter()
        errors: list[str] = []
        cancelled = False

        try:
            for module_key in self.modules_to_run:
                if self.isInterruptionRequested():
                    cancelled = True
                    log.info("Run cancelled before module %s", module_key)
                    break

                display_name = MODULE_DISPLAY_NAMES.get(module_key, module_key)
                self.module_started.emit(display_name)
                self.progress_message.emit(f"Starting: {display_name}")
                module_start = time.perf_counter()

                try:
                    if module_key == "network_info":
                        self._network_info = NetworkInfoCollector().collect()
                        self.network_info_ready.emit(self._network_info)
                        log.info("Network info collected in %.1f s",
                                 time.perf_counter() - module_start)
                        continue

                    report = self._run_module(module_key)
                    if report is None:
                        continue
                    report.finish()
                    self._module_reports.append(report)
                    self.module_finished.emit(report)
                    log.info("Module '%s' finished in %.1f s with status %s",
                             display_name, time.perf_counter() - module_start,
                             report.overall_status.value)
                except Exception as exc:  # noqa: BLE001 - one module must never kill the run
                    log.exception("Module %s raised an exception", module_key)
                    errors.append(f"{display_name}: {exc}")
                    failed = ModuleReport(module_name=display_name)
                    failed.add(CheckResult(
                        name=display_name,
                        status=Status.UNKNOWN,
                        message=f"This module could not complete due to an internal error: {exc}",
                    ))
                    failed.finish()
                    self._module_reports.append(failed)
                    self.module_finished.emit(failed)

            duration = time.perf_counter() - started
            interpretations = ResultAnalyzer().analyze(self._network_info, self._module_reports)
            full_report = FullReport(
                network_info=self._network_info,
                modules=self._module_reports,
                interpretations=interpretations,
                generated_at=started_wall,
                profile_name=self.profile_name,
                duration_seconds=round(duration, 2),
                cancelled=cancelled,
                target_host=self.target_host,
            )
            self._log_run_summary(full_report, errors)
            self.progress_message.emit("Run cancelled." if cancelled else "All tests completed.")
            self.run_finished.emit(full_report)

        except Exception as exc:  # noqa: BLE001 - the run must never crash the app
            log.exception("Diagnostic run failed")
            self.run_failed.emit(str(exc))

    # ------------------------------------------------------------------ #
    def _log_run_summary(self, report: FullReport, errors: list[str]) -> None:
        info = report.network_info
        log.info(
            "RUN SUMMARY | started=%s | duration=%.1fs | cancelled=%s | modules=%d | errors=%d",
            report.generated_at.strftime("%Y-%m-%d %H:%M:%S"), report.duration_seconds or 0.0,
            report.cancelled, len(report.modules), len(errors),
        )
        log.info(
            "RUN NETWORK | public_ip=%s | isp=%s | country=%s | ipv4=%s | ipv6=%s | dns=%s | gateway=%s",
            info.public_ip, info.isp, info.country, info.ipv4_available, info.ipv6_available,
            ",".join(info.dns_servers) or "-", info.gateway,
        )
        for message in errors:
            log.error("RUN ERROR | %s", message)

    def _run_module(self, module_key: str) -> Optional[ModuleReport]:
        cb: Callable[[str], None] = self.progress_message.emit

        if module_key == "environment_check":
            return EnvironmentChecker(progress_cb=cb).run_all()
        if module_key == "basic_connectivity":
            return BasicConnectivityTester(
                target_host=self.target_host or "1.1.1.1", progress_cb=cb).run_all()
        if module_key == "dns_test":
            return DNSTester().run_all()
        if module_key == "tcp_scanner":
            return TCPScanner(
                target_host=self.target_host, ports=self.tcp_ports, progress_cb=cb).run_all()
        if module_key == "udp_test":
            return UDPTester(
                target_host=self.target_host, ports=self.udp_ports, progress_cb=cb).run_all()
        if module_key == "tls_test":
            return TLSTester(progress_cb=cb).run_all()
        if module_key == "http_test":
            return HTTPTester(progress_cb=cb).run_all()
        if module_key == "tcp_stall":
            return TCPStallTester(progress_cb=cb).run_all()
        if module_key == "site_reachability":
            return SiteReachabilityTester(test_hosts=self.test_sites, progress_cb=cb).run_all()
        if module_key == "protocol_tests":
            return ProtocolTester(progress_cb=cb).run_all()
        if module_key == "latency_test":
            targets = dict(LATENCY_TARGETS)
            if self.target_host:
                targets["Custom target"] = self.target_host
            return LatencyTester(targets=targets, progress_cb=cb).run_all()
        if module_key == "mtu_test":
            return MTUTester(host=self.target_host or "1.1.1.1", progress_cb=cb).run_all()
        if module_key == "vpn_connectivity":
            return VPNConnectivityTester(progress_cb=cb).run_all()
        if module_key == "protocol_whitelist":
            return ProtocolWhitelistProbe(progress_cb=cb).run_all()

        log.warning("Unknown module key requested: %s", module_key)
        return None
