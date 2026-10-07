"""
tcp_scanner.py
==============
A deliberately restricted TCP connectivity checker. It only ever
connects to ports from :data:`app.constants.ALLOWED_TCP_PORTS`, against
a small set of well known, always-on anycast hosts (Cloudflare / Google).
This is a *diagnostic* scanner (is port 443 reachable from this network?)
- not a general purpose port scanner aimed at arbitrary targets.
"""

from __future__ import annotations

import errno
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Optional

from app.constants import (
    ALLOWED_TCP_PORTS,
    MAX_THREAD_WORKERS,
    PORT_SERVICE_NAMES,
    TCP_SCAN_TARGETS,
    TCP_TIMEOUT,
)
from app.logger import get_logger
from app.models import CheckResult, ModuleReport, Status

log = get_logger(__name__)

ProgressCallback = Optional[Callable[[str], None]]


# Error codes differ between Windows (WSA*) and POSIX, so both are listed.
_REFUSED = {errno.ECONNREFUSED, 10061}
_RESET = {errno.ECONNRESET, errno.ECONNABORTED, 10054, 10053}
_TIMEOUT = {errno.ETIMEDOUT, errno.EAGAIN, errno.EWOULDBLOCK, 10060, 10035}


def classify_connect_result(code: int) -> str:
    """
    Map a ``connect_ex`` result to one of:
    open / closed / reset / timeout / filtered.

    closed   - the host actively refused (RST on SYN): nothing listens there
    reset    - the connection was torn down after it started (often a middlebox)
    timeout  - complete silence within the time limit (dropped packets)
    filtered - any other error, e.g. ICMP "unreachable" from the network
    """
    if code == 0:
        return "open"
    if code in _REFUSED:
        return "closed"
    if code in _RESET:
        return "reset"
    if code in _TIMEOUT:
        return "timeout"
    return "filtered"


class PortProbeResult:
    __slots__ = ("port", "state", "latency_ms", "note")

    def __init__(self, port: int, state: str, latency_ms: Optional[float], note: str = "") -> None:
        self.port = port
        self.state = state  # open / closed / filtered / timeout / reset
        self.latency_ms = latency_ms
        self.note = note


class TCPScanner:
    """Scans a fixed allow-list of TCP ports against a chosen target."""

    def __init__(
        self,
        target_host: Optional[str] = None,
        ports: Optional[list[int]] = None,
        progress_cb: ProgressCallback = None,
    ) -> None:
        self.target_host = target_host or TCP_SCAN_TARGETS["Cloudflare"]
        requested = ports or ALLOWED_TCP_PORTS
        # Hard enforcement: never scan a port outside the allow-list, no
        # matter what the caller (including advanced mode) passes in.
        self.ports = [p for p in requested if p in ALLOWED_TCP_PORTS]
        self.progress_cb = progress_cb

    def _report(self, message: str) -> None:
        if self.progress_cb:
            self.progress_cb(message)
        log.info(message)

    def probe_port(self, port: int) -> PortProbeResult:
        start = time.perf_counter()
        code: int
        note = ""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(TCP_TIMEOUT)
                code = sock.connect_ex((self.target_host, port))
        except socket.timeout:
            code = errno.ETIMEDOUT
        except socket.gaierror as exc:
            code = -1
            note = f"could not resolve target: {exc}"
        except OSError as exc:
            code = exc.errno if exc.errno is not None else -1
            note = str(exc)

        latency_ms = (time.perf_counter() - start) * 1000.0
        state = classify_connect_result(code)
        if not note and code != 0:
            note = f"errno={code}"
        return PortProbeResult(port, state, latency_ms, note=note)

    def run_all(self) -> ModuleReport:
        report = ModuleReport(module_name="TCP Port Scanner")
        self._report(f"Scanning {len(self.ports)} TCP ports on {self.target_host} ...")

        results: dict[int, PortProbeResult] = {}
        with ThreadPoolExecutor(max_workers=min(MAX_THREAD_WORKERS, len(self.ports) or 1)) as pool:
            futures = {pool.submit(self.probe_port, port): port for port in self.ports}
            for future in as_completed(futures):
                port = futures[future]
                try:
                    results[port] = future.result()
                except Exception as exc:  # pragma: no cover - defensive
                    results[port] = PortProbeResult(port, "filtered", None, note=str(exc))

        open_ports = []
        for port in sorted(results.keys()):
            probe = results[port]
            service = PORT_SERVICE_NAMES.get(port, "Unknown")
            status_map = {
                "open": Status.OK,
                "closed": Status.WARNING,
                "filtered": Status.WARNING,
                "timeout": Status.WARNING,
                "reset": Status.FAILED,
            }
            status = status_map.get(probe.state, Status.UNKNOWN)
            if probe.state == "open":
                open_ports.append(port)

            report.add(
                CheckResult(
                    name=f"TCP {port} ({service})",
                    status=status,
                    message=f"{probe.state.upper()}"
                    + (f" - {probe.latency_ms:.0f} ms" if probe.latency_ms else ""),
                    details={
                        "port": port,
                        "service": service,
                        "state": probe.state,
                        "latency_ms": probe.latency_ms,
                        "target": self.target_host,
                        "note": probe.note,
                    },
                    duration_ms=probe.latency_ms,
                )
            )

        report.finish()
        log.info("TCP scan complete. Open ports: %s", open_ports)
        return report
