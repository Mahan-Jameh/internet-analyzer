"""
gateway.py
==========
Local-network diagnostics that run *before* anything depends on the Internet:
is there a usable local interface and default route, and does the default
gateway answer?

The gateway test uses ICMP first and, if that is silent, TCP connects to the
ports a home router usually serves (53/80/443). A TCP *refusal* counts as an
answer: it proves the gateway is alive. A router that ignores both is reported
as "not answering" with moderate confidence only - many routers do.
"""

from __future__ import annotations

import threading
from typing import Callable, Optional

from app.core.icmp import ping_result
from app.diag.adapter import check_from_result
from app.diag.localnet import LocalNetwork, collect_local_network
from app.diag.probes import tcp_probe
from app.diag.results import Severity, TechnicalStatus, TestResult
from app.diag.testconfig import DEFAULT_CONFIG, NetworkTestConfig
from app.logger import get_logger
from app.models import ModuleReport

log = get_logger(__name__)
_S = TechnicalStatus

ProgressCallback = Optional[Callable[[str], None]]
GATEWAY_TCP_PORTS = (80, 443, 53)


class GatewayTester:
    def __init__(self, progress_cb: ProgressCallback = None, config: NetworkTestConfig = DEFAULT_CONFIG,
                 cancel: Optional[threading.Event] = None, local: Optional[LocalNetwork] = None,
                 ping=ping_result, tcp=tcp_probe) -> None:  # noqa: ANN001 - injectable for tests
        self.progress_cb = progress_cb
        self.config = config
        self.cancel = cancel or threading.Event()
        self._local = local
        self._ping, self._tcp = ping, tcp

    def _report(self, message: str) -> None:
        if self.progress_cb:
            self.progress_cb(message)
        log.info(message)

    # ------------------------------------------------------------------ #
    def check_interface(self, local: LocalNetwork) -> TestResult:
        res = TestResult("local_interface", "local", protocol="IP",
                         metrics={"ipv4_address": local.ipv4.address, "ipv6_address": local.ipv6.address,
                                  "adapter": local.adapter_name, "dns_servers": local.dns,
                                  "default_routes_v4": [r.to_dict() for r in local.routes_v4],
                                  "default_routes_v6": [r.to_dict() for r in local.routes_v6]})
        if local.ipv4.usable or local.ipv6.usable:
            res.status = _S.SUCCESS
            res.summary = ("Local interface is configured"
                           + (f" ({local.adapter_name})" if local.adapter_name else "")
                           + f": IPv4 {local.ipv4.address or 'none'}.")
            res.add_evidence(f"Source address {local.ipv4.address or local.ipv6.address} selected by the routing table")
            if len(local.routes_v4) > 1:
                res.warnings.append(f"{len(local.routes_v4)} default routes exist (a VPN or second adapter may be active).")
        else:
            res.status, res.severity = _S.UNREACHABLE, Severity.CRITICAL
            res.error_code = "NO_ADDRESS"
            res.summary = "No usable local network address was found (cable/Wi-Fi disconnected?)."
            res.add_evidence("The routing table could not select a source address for IPv4 or IPv6.")
        return res

    def check_gateway(self, local: LocalNetwork) -> TestResult:
        gw = local.gateway
        res = TestResult("gateway", "gateway", target=gw, protocol="ICMP/TCP", address_family="IPv4")
        if not gw:
            if local.routes_v4:   # on-link default route: typical for tunnel adapters
                res.status, res.severity = _S.NOT_APPLICABLE, Severity.INFO
                res.summary = "The default route is on-link (no gateway address), as with a VPN/tunnel adapter."
                res.metadata["skip_reason"] = "NO_GATEWAY_ADDRESS"
            elif local.ipv4.usable:
                res.status, res.severity = _S.UNKNOWN, Severity.INFO
                res.summary = "The default gateway could not be determined on this system."
            else:
                res.status, res.severity = _S.UNREACHABLE, Severity.ERROR
                res.error_code = "NO_DEFAULT_ROUTE"
                res.summary = "There is no default route, so no traffic can leave this network."
                res.add_evidence("No IPv4 default route in the routing table.")
            return res

        self._report(f"Checking the local gateway {gw} ...")
        icmp = self._ping(gw, 3, self.config, family="IPv4", test_id=f"icmp.gateway.{gw}", role="gateway")
        res.metrics["icmp"] = icmp.metrics
        res.duration_ms = icmp.duration_ms
        if icmp.ok:
            res.status = _S.SUCCESS
            res.summary = f"The gateway {gw} answers ping ({icmp.metrics.get('average_ms')} ms)."
            res.add_evidence(f"{icmp.metrics.get('packets_received')} echo replies from {gw}")
            return res
        if icmp.status is _S.PARTIAL:
            res.status, res.severity = _S.PARTIAL, Severity.WARNING
            res.summary = f"The gateway {gw} answers with packet loss ({icmp.metrics.get('packet_loss_percent')}%)."
            return res

        tcp_alive: list[str] = []
        for port in GATEWAY_TCP_PORTS:
            if self.cancel.is_set():
                break
            probe = self._tcp(gw, port, self.config, role="gateway", retry=False, test_id=f"tcp.gateway.{port}")
            res.metrics.setdefault("tcp", {})[str(port)] = probe.status.value
            if probe.status in (_S.OPEN, _S.CLOSED):         # a refusal also proves the host is alive
                tcp_alive.append(f"{port}={probe.status.value}")
                break
        if tcp_alive:
            res.status = _S.SUCCESS
            res.summary = f"The gateway {gw} does not answer ping but responds on TCP ({tcp_alive[0]})."
            res.add_evidence(f"TCP port answered: {tcp_alive[0]}")
            res.warnings.append("ICMP echo to the gateway is blocked or ignored.")
        else:
            res.status, res.severity = _S.TIMEOUT, Severity.WARNING
            res.error_code, res.interpretation, res.confidence = "TIMEOUT", "GATEWAY_NOT_ANSWERING", 0.5
            res.summary = (f"The gateway {gw} did not answer ping or TCP probes. Many routers ignore both, "
                           "so this is only a hint of a local network problem.")
            res.add_evidence("No ICMP reply and no TCP answer from the gateway.")
        return res

    def run_all(self) -> ModuleReport:
        report = ModuleReport(module_name="Local Network & Gateway")
        local = self._local or collect_local_network()
        iface = self.check_interface(local)
        report.add(check_from_result("Local Interface", iface, details={"adapter": local.adapter_name}))
        if not self.cancel.is_set():
            gw = self.check_gateway(local)
            report.add(check_from_result("Default Gateway", gw, details={"gateway": local.gateway}))
        report.finish()
        return report
