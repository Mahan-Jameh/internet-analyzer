"""
runner.py
=========
Qt-free orchestration of the diagnostic modules on top of the dependency graph.

    local_network ──soft──> dns_test ──hard──> tls_test / http_test / site_reachability / tcp_stall
                                  └──soft──> basic_connectivity

* ``hard``: a name-based test is not run when system DNS resolution is *proven*
  to fail; it is reported as SKIPPED (blocked by dependency) instead of adding a
  string of misleading secondary failures.
* ``soft``: ordering only (e.g. a silent gateway never blocks the DNS tests).
* ``exclusive``: measurement-sensitive modules (latency, MTU, bulk transfer,
  protocol probe) get the network to themselves.

Independent modules run concurrently, bounded by ``config.max_concurrency``.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

from app.constants import LATENCY_TARGETS
from app.core.basic_connectivity import BasicConnectivityTester
from app.core.dns_test import DNSTester
from app.core.environment_check import EnvironmentChecker
from app.core.gateway import GatewayTester
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
from app.diag.adapter import check_from_result, results_of
from app.diag.graph import SKIP_BLOCKED, DependencyGraph, GraphRunner, Node, RunContext
from app.diag.results import TechnicalStatus, TestResult
from app.diag.structlog import log_result
from app.diag.testconfig import DEFAULT_CONFIG, NetworkTestConfig
from app.logger import get_logger
from app.models import CheckResult, ModuleReport, NetworkInfo, Status

log = get_logger(__name__)

ALL_MODULES = [
    "network_info", "local_network", "environment_check", "basic_connectivity", "dns_test",
    "tcp_scanner", "udp_test", "tls_test", "http_test", "tcp_stall", "site_reachability",
    "protocol_tests", "latency_test", "mtu_test", "vpn_connectivity", "protocol_whitelist",
]
OPT_IN_MODULES = {"protocol_whitelist"}
DEFAULT_MODULES = [m for m in ALL_MODULES if m not in OPT_IN_MODULES]

MODULE_DISPLAY_NAMES = {
    "network_info": "Network Information",
    "local_network": "Local Network & Gateway",
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

# module -> (hard dependencies, soft dependencies, exclusive)
MODULE_DEPENDENCIES: dict[str, tuple[tuple[str, ...], tuple[str, ...], bool]] = {
    "dns_test": ((), ("local_network",), False),
    "basic_connectivity": ((), ("local_network",), False),
    "tls_test": (("dns_test",), (), False),
    "http_test": (("dns_test",), (), False),
    "site_reachability": (("dns_test",), (), False),
    "tcp_stall": (("dns_test",), (), True),
    "protocol_whitelist": (("dns_test",), (), True),
    "latency_test": ((), ("local_network",), True),
    "mtu_test": ((), ("latency_test",), True),
}


def normalize_modules(requested: Optional[list[str]]) -> list[str]:
    """Keep only known modules, in canonical order, with network_info always first."""
    wanted = set(requested) if requested else set(DEFAULT_MODULES)
    wanted.add("network_info")
    return [m for m in ALL_MODULES if m in wanted]


def dns_gate(results: list[TestResult]) -> bool:
    """
    Passes unless system resolution was *proven* to fail: if no system-resolver
    result exists at all (module crashed, nothing measured) the dependency is
    unknown, and unknown must not block.
    """
    system = [r for r in results if r.category == "dns_resolution" and r.metadata.get("role") == "system"
              and not r.skipped]
    return True if not system else any(r.ok for r in system)


@dataclass
class RunParams:
    target_host: Optional[str] = None
    tcp_ports: Optional[list[int]] = None
    udp_ports: Optional[list[int]] = None
    test_sites: Optional[list[str]] = None


@dataclass
class RunOutput:
    network_info: NetworkInfo = field(default_factory=NetworkInfo)
    reports: list[ModuleReport] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    cancelled: bool = False


class DiagnosticRunner:
    def __init__(
        self,
        modules: list[str],
        params: RunParams | None = None,
        config: NetworkTestConfig = DEFAULT_CONFIG,
        cancel: threading.Event | None = None,
        progress: Callable[[str], None] | None = None,
        on_module_started: Callable[[str], None] | None = None,
        on_module_finished: Callable[[ModuleReport], None] | None = None,
        on_network_info: Callable[[NetworkInfo], None] | None = None,
    ) -> None:
        self.modules = modules
        self.params = params or RunParams()
        self.config = config
        self.cancel = cancel or threading.Event()
        self.progress = progress or (lambda _m: None)
        self.on_module_started = on_module_started
        self.on_module_finished = on_module_finished
        self.on_network_info = on_network_info
        self.output = RunOutput()
        self._lock = threading.Lock()
        self._reports: dict[str, ModuleReport] = {}

    # ------------------------------------------------------------------ #
    def build_graph(self) -> DependencyGraph:
        nodes = []
        for key in self.modules:
            hard, soft, exclusive = MODULE_DEPENDENCIES.get(key, ((), (), False))
            nodes.append(Node(
                node_id=key, run=lambda ctx, k=key: self._run_node(k, ctx), hard=hard, soft=soft,
                exclusive=exclusive, layer=key,
                gate=dns_gate if key == "dns_test" else (lambda results: True)))
        return DependencyGraph(nodes)

    def run(self) -> RunOutput:
        graph = self.build_graph()
        runner = GraphRunner(graph, max_workers=self.config.max_concurrency, cancel=self.cancel,
                             on_start=self._on_start, on_done=self._on_done)
        ctx = runner.run()
        self.output.cancelled = self.cancel.is_set()
        for key, results in ctx.results.items():
            if key not in self._reports and key != "network_info":     # skipped / cancelled before start
                self._reports[key] = self._skipped_report(key, results)
        # canonical order, whatever order they finished in
        self.output.reports = [self._reports[k] for k in self.modules
                               if k in self._reports and k != "network_info"]
        return self.output

    # ------------------------------------------------------------------ #
    def _display(self, key: str) -> str:
        return MODULE_DISPLAY_NAMES.get(key, key)

    def _on_start(self, node: Node) -> None:
        name = self._display(node.node_id)
        if self.on_module_started:
            self.on_module_started(name)
        self.progress(f"Starting: {name}")

    def _on_done(self, node: Node, results: list[TestResult]) -> None:
        key = node.node_id
        if key == "network_info":
            return
        report = self._reports.get(key)
        if report is None:                                           # never ran: blocked or cancelled
            report = self._skipped_report(key, results)
            self._reports[key] = report
        if self.on_module_finished:
            self.on_module_finished(report)

    def _skipped_report(self, key: str, results: list[TestResult]) -> ModuleReport:
        name = self._display(key)
        report = ModuleReport(module_name=name)
        res = results[0] if results else TestResult(key, "node", status=TechnicalStatus.SKIPPED)
        blocked = res.metadata.get("blocked_by") or []
        why = res.metadata.get("skip_reason")
        if why == SKIP_BLOCKED:
            names = ", ".join(self._display(b) for b in blocked)
            msg = (f"Skipped: {names} did not succeed, so this test would only repeat that failure.")
        else:
            msg = "Skipped: the diagnostic was cancelled before this test started."
        report.add(check_from_result(name, res, message=msg, details={"skipped": True, "blocked_by": blocked}))
        report.results.append(res)
        report.finish()
        return report

    # ------------------------------------------------------------------ #
    def _run_node(self, key: str, ctx: RunContext) -> list[TestResult]:
        started = time.perf_counter()
        if key == "network_info":
            info = NetworkInfoCollector(self.config, self.cancel).collect()
            self.output.network_info = info
            if self.on_network_info:
                self.on_network_info(info)
            for result in info.test_results:
                log_result(log, result)
            log.info("Network info collected in %.1f s", time.perf_counter() - started)
            return list(info.test_results)
        try:
            report = self._make_module(key)
            if report is None:
                return [TestResult(key, "node", status=TechnicalStatus.NOT_APPLICABLE, summary="Unknown module.")]
        except Exception as exc:  # noqa: BLE001 - one module must never kill the run
            log.exception("Module %s raised an exception", key)
            name = self._display(key)
            with self._lock:
                self.output.errors.append(f"{name}: {exc}")
            report = ModuleReport(module_name=name)
            report.add(CheckResult(name=name, status=Status.UNKNOWN,
                                   message=f"This module could not complete due to an internal error: {exc}"))
        report.finish()
        with self._lock:
            self._reports[key] = report
        for result in results_of([report]):
            log_result(log, result)
        log.info("Module '%s' finished in %.1f s with status %s", self._display(key),
                 time.perf_counter() - started, report.overall_status.value)
        return results_of([report]) or [TestResult(key, "node", status=TechnicalStatus.INCONCLUSIVE)]

    def _make_module(self, key: str) -> Optional[ModuleReport]:
        cb, cfg, cancel, p = self.progress, self.config, self.cancel, self.params
        if key == "local_network":
            return GatewayTester(progress_cb=cb, config=cfg, cancel=cancel).run_all()
        if key == "environment_check":
            return EnvironmentChecker(progress_cb=cb, cancel=cancel).run_all()
        if key == "basic_connectivity":
            return BasicConnectivityTester(target_host=p.target_host or "1.1.1.1", progress_cb=cb,
                                           config=cfg, cancel=cancel).run_all()
        if key == "dns_test":
            return DNSTester(config=cfg, cancel=cancel).run_all()
        if key == "tcp_scanner":
            return TCPScanner(target_host=p.target_host, ports=p.tcp_ports, progress_cb=cb,
                              config=cfg, cancel=cancel).run_all()
        if key == "udp_test":
            return UDPTester(target_host=p.target_host, ports=p.udp_ports, progress_cb=cb,
                             config=cfg, cancel=cancel).run_all()
        if key == "tls_test":
            return TLSTester(progress_cb=cb, config=cfg, cancel=cancel).run_all()
        if key == "http_test":
            return HTTPTester(progress_cb=cb, config=cfg, cancel=cancel).run_all()
        if key == "tcp_stall":
            return TCPStallTester(progress_cb=cb, cancel=cancel).run_all()
        if key == "site_reachability":
            return SiteReachabilityTester(test_hosts=p.test_sites, progress_cb=cb, config=cfg,
                                          cancel=cancel).run_all()
        if key == "protocol_tests":
            return ProtocolTester(progress_cb=cb, config=cfg, cancel=cancel).run_all()
        if key == "latency_test":
            targets = dict(LATENCY_TARGETS)
            if p.target_host:
                targets["Custom target"] = p.target_host
            return LatencyTester(targets=targets, progress_cb=cb, config=cfg, cancel=cancel).run_all()
        if key == "mtu_test":
            return MTUTester(host=p.target_host or "1.1.1.1", progress_cb=cb, config=cfg, cancel=cancel).run_all()
        if key == "vpn_connectivity":
            return VPNConnectivityTester(progress_cb=cb, config=cfg, cancel=cancel).run_all()
        if key == "protocol_whitelist":
            return ProtocolWhitelistProbe(progress_cb=cb).run_all()
        log.warning("Unknown module key requested: %s", key)
        return None
