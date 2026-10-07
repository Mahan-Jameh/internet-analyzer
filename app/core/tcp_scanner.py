"""
tcp_scanner.py
==============
A deliberately restricted TCP connectivity checker. It only ever connects to
ports from :data:`app.constants.ALLOWED_TCP_PORTS`, against a target chosen by
the user (or a public default). This is a *diagnostic* tool - "is port 443
reachable from this network?" - not a general purpose port scanner.

Method: plain TCP *connect* scanning with the standard socket API (portable,
no raw packets, no admin rights). Result semantics are documented in
:mod:`app.diag.probes`; in short: OPEN = handshake completed, CLOSED = actively
refused, TIMEOUT = silence (never reported as closed), UNREACHABLE = no route.
"""

from __future__ import annotations

import errno
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Optional

from app.constants import ALLOWED_TCP_PORTS, PORT_SERVICE_NAMES, TCP_SCAN_TARGETS
from app.diag.adapter import check_from_result
from app.diag.neterrors import classify_os_error
from app.diag.probes import refine_timeouts, resolve, tcp_probe
from app.diag.results import Severity, TechnicalStatus, TestResult
from app.diag.testconfig import DEFAULT_CONFIG, NetworkTestConfig
from app.logger import get_logger
from app.models import ModuleReport

log = get_logger(__name__)

ProgressCallback = Optional[Callable[[str], None]]

# Ports whose reachability matters for ordinary browsing: a refusal there is notable.
_WEB_PORTS = {80, 443}

_LEGACY_STATE = {
    TechnicalStatus.OPEN: "open", TechnicalStatus.CLOSED: "closed", TechnicalStatus.TIMEOUT: "timeout",
    TechnicalStatus.RESET: "reset", TechnicalStatus.UNREACHABLE: "unreachable",
    TechnicalStatus.ERROR: "error", TechnicalStatus.DNS_FAILED: "dns_failed",
}


def classify_connect_result(code: int) -> str:
    """
    Map a ``connect_ex`` result to open / closed / reset / timeout / unreachable / error.
    (Kept for compatibility; the scanner itself uses :mod:`app.diag.neterrors`.)
    """
    if code == 0:
        return "open"
    name = classify_os_error(code)
    return {
        "CONNECTION_REFUSED": "closed",
        "CONNECTION_RESET": "reset", "CONNECTION_ABORTED": "reset",
        "TIMEOUT": "timeout", "WOULD_BLOCK": "timeout",
        "NETWORK_UNREACHABLE": "unreachable", "HOST_UNREACHABLE": "unreachable", "NETWORK_DOWN": "unreachable",
    }.get(name or "", "error")


class PortProbeResult:
    """Compatibility view of one probe (state strings are lowercase)."""

    __slots__ = ("port", "state", "latency_ms", "note", "result")

    def __init__(self, port: int, state: str, latency_ms: Optional[float], note: str = "",
                 result: Optional[TestResult] = None) -> None:
        self.port = port
        self.state = state
        self.latency_ms = latency_ms
        self.note = note
        self.result = result


class TCPScanner:
    """Scans a fixed allow-list of TCP ports against a chosen target."""

    def __init__(
        self,
        target_host: Optional[str] = None,
        ports: Optional[list[int]] = None,
        progress_cb: ProgressCallback = None,
        config: NetworkTestConfig = DEFAULT_CONFIG,
        cancel: Optional[threading.Event] = None,
        family: Optional[str] = None,
    ) -> None:
        self.target_host = target_host or TCP_SCAN_TARGETS["Cloudflare"]
        requested = ports or ALLOWED_TCP_PORTS
        # Hard enforcement: never scan a port outside the allow-list, no matter
        # what the caller (including advanced mode) passes in.
        self.ports = [p for p in requested if p in ALLOWED_TCP_PORTS]
        self.progress_cb = progress_cb
        self.config = config
        self.cancel = cancel or threading.Event()
        self.family = family

    def _report(self, message: str) -> None:
        if self.progress_cb:
            self.progress_cb(message)
        log.info(message)

    # -- single port ------------------------------------------------------
    def scan_port(self, port: int, resolution=None) -> TestResult:  # noqa: ANN001
        result = tcp_probe(self.target_host, port, self.config, family=self.family,
                           resolution=resolution, role="scan" if port not in _WEB_PORTS else "reachability",
                           cancel=self.cancel)
        if result.category == "tcp":
            result.metadata["service"] = PORT_SERVICE_NAMES.get(port, "Unknown")
            if result.status is TechnicalStatus.CLOSED:
                result.severity = Severity.WARNING if port in _WEB_PORTS else Severity.INFO
        return result

    def probe_port(self, port: int) -> PortProbeResult:
        """Compatibility wrapper returning the lowercase-state view."""
        res = self.scan_port(port)
        state = _LEGACY_STATE.get(res.status, "error")
        return PortProbeResult(port, state, res.duration_ms, note=res.error_message or "", result=res)

    # -- whole scan ---------------------------------------------------------
    def scan(self) -> list[TestResult]:
        self._report(f"Scanning {len(self.ports)} TCP ports on {self.target_host} ...")
        resolution = resolve(self.target_host, self.family)
        if not resolution.ok:
            from app.diag.probes import dns_failure_result
            dns = dns_failure_result(f"dns.{self.target_host}", self.target_host, resolution)
            skipped = [self._skipped(p, "dns") for p in self.ports]
            return [dns, *skipped]

        results: dict[int, TestResult] = {}
        workers = max(1, min(self.config.scan_concurrency, len(self.ports) or 1))
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="icpa-tcp") as pool:
            futures = {pool.submit(self._safe_scan, p, resolution): p for p in self.ports}
            for future in as_completed(futures):
                results[futures[future]] = future.result()
        ordered = [results[p] for p in sorted(results)]
        refine_timeouts(ordered)
        return ordered

    def _safe_scan(self, port: int, resolution) -> TestResult:  # noqa: ANN001
        if self.cancel.is_set():
            return self._skipped(port, "cancelled")
        try:
            return self.scan_port(port, resolution)
        except Exception as exc:  # noqa: BLE001 - one port must not break the scan
            log.exception("TCP probe of port %s crashed", port)
            return TestResult(f"tcp.{self.target_host}.{port}", "tcp", status=TechnicalStatus.ERROR,
                              target=self.target_host, port=port, protocol="TCP",
                              error_type=type(exc).__name__, error_message=str(exc)[:200],
                              summary=f"Port {port} could not be tested (internal error).")

    def _skipped(self, port: int, why: str) -> TestResult:
        r = TestResult(f"tcp.{self.target_host}.{port}", "tcp", status=TechnicalStatus.SKIPPED,
                       target=self.target_host, port=port, protocol="TCP",
                       summary="Not tested: name resolution failed." if why == "dns" else "Not tested: cancelled.")
        r.metadata.update(skip_reason="BLOCKED_BY_DEPENDENCY" if why == "dns" else "CANCELLED",
                          blocked_by=[f"dns.{self.target_host}"] if why == "dns" else [])
        return r

    def run_all(self) -> ModuleReport:
        report = ModuleReport(module_name="TCP Port Scanner")
        results = self.scan()
        open_ports: list[int] = []
        for res in results:
            if res.category == "dns_resolution":
                report.add(check_from_result(f"DNS {self.target_host}", res, details={"target": self.target_host}))
                continue
            port = res.port or 0
            service = PORT_SERVICE_NAMES.get(port, "Unknown")
            state = _LEGACY_STATE.get(res.status, res.status.value.lower())
            if res.status is TechnicalStatus.OPEN:
                open_ports.append(port)
            msg = state.upper()
            if res.status is TechnicalStatus.TIMEOUT:
                msg = "TIMEOUT - no response; possibly filtered (not proof that it is closed)"
            elif res.duration_ms and res.status is TechnicalStatus.OPEN:
                msg += f" - {res.duration_ms:.0f} ms"
            if res.status is TechnicalStatus.SKIPPED:
                msg = "SKIPPED - " + res.summary
            report.add(check_from_result(
                f"TCP {port} ({service})", res, message=msg,
                details={"port": port, "service": service, "state": state, "latency_ms": res.duration_ms,
                         "target": self.target_host, "note": res.error_message or "",
                         "ip": res.resolved_ip, "family": res.address_family,
                         "attempts": res.attempts, "retry_outcome": res.retry_outcome.value}))
        report.finish()
        log.info("TCP scan complete. Open ports: %s", open_ports)
        return report
