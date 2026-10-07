"""
udp_test.py
===========
UDP is connectionless, so "is this port open" cannot be determined the
same way as TCP. Instead this module sends a protocol-appropriate probe
packet (a real DNS query for port 53, a real NTP request for port 123)
and, for other ports, a generic payload - then classifies the outcome:

    REACHABLE  - we received a response
    NO_RESPONSE - no response within the timeout (could be normal
                  UDP behaviour, or the traffic could be silently
                  dropped/blocked - both look identical to a client)
    BLOCKED    - we received an explicit ICMP "port unreachable",
                  meaning something on the path actively rejected it
"""

from __future__ import annotations

import socket
import time
from typing import Callable, Optional

from app.constants import ALLOWED_UDP_PORTS, UDP_PORT_NAMES, UDP_TIMEOUT
from app.logger import get_logger
from app.models import CheckResult, ModuleReport, Status

log = get_logger(__name__)

ProgressCallback = Optional[Callable[[str], None]]

# A minimal, valid DNS query for "example.com A" - used to probe port 53
# because a real DNS query is far more likely to get a genuine reply than
# an arbitrary payload.
_DNS_PROBE = (
    b"\x12\x34"          # transaction id
    b"\x01\x00"          # flags: standard query
    b"\x00\x01\x00\x00\x00\x00\x00\x00"  # 1 question
    b"\x07example\x03com\x00"            # example.com
    b"\x00\x01\x00\x01"  # type A, class IN
)

# A minimal SNTP client request packet (RFC 4330) - used to probe port 123.
_NTP_PROBE = b"\x1b" + 47 * b"\0"

_DEFAULT_PROBE = b"ICPA-DIAGNOSTIC-PROBE"


def _probe_payload(port: int) -> bytes:
    if port == 53:
        return _DNS_PROBE
    if port == 123:
        return _NTP_PROBE
    return _DEFAULT_PROBE


class UDPTester:
    def __init__(
        self,
        target_host: Optional[str] = None,
        ports: Optional[list[int]] = None,
        progress_cb: ProgressCallback = None,
    ) -> None:
        # Different UDP services live on different hosts; use sensible,
        # always-on public anycast defaults per port unless overridden.
        self._default_targets = {
            53: "1.1.1.1",
            123: "pool.ntp.org",
            443: "1.1.1.1",     # QUIC / HTTP3
            500: "8.8.8.8",     # arbitrary reachable host for IKE probe
            4500: "8.8.8.8",
            51820: "8.8.8.8",
        }
        self.target_host_override = target_host
        requested = ports or ALLOWED_UDP_PORTS
        self.ports = [p for p in requested if p in ALLOWED_UDP_PORTS]
        self.progress_cb = progress_cb

    def _report(self, message: str) -> None:
        if self.progress_cb:
            self.progress_cb(message)
        log.info(message)

    def probe_port(self, port: int) -> CheckResult:
        target = self.target_host_override or self._default_targets.get(port, "1.1.1.1")
        service = UDP_PORT_NAMES.get(port, "Unknown")
        payload = _probe_payload(port)

        start = time.perf_counter()
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(UDP_TIMEOUT)
                try:
                    resolved = socket.gethostbyname(target)
                except socket.gaierror:
                    return CheckResult(
                        name=f"UDP {port} ({service})",
                        status=Status.UNKNOWN,
                        message=f"Could not resolve target host '{target}'.",
                        details={"port": port, "target": target},
                    )

                sock.sendto(payload, (resolved, port))
                try:
                    data, _addr = sock.recvfrom(2048)
                    latency_ms = (time.perf_counter() - start) * 1000.0
                    return CheckResult(
                        name=f"UDP {port} ({service})",
                        status=Status.OK,
                        message=f"Reachable - received {len(data)} byte response in {latency_ms:.0f} ms.",
                        details={"port": port, "target": resolved, "response_bytes": len(data)},
                        duration_ms=latency_ms,
                    )
                except socket.timeout:
                    latency_ms = (time.perf_counter() - start) * 1000.0
                    return CheckResult(
                        name=f"UDP {port} ({service})",
                        status=Status.WARNING,
                        message="No response within timeout (may be normal for UDP, or blocked).",
                        details={"port": port, "target": resolved, "outcome": "no_response"},
                        duration_ms=latency_ms,
                    )
                except ConnectionResetError:
                    # On Windows, an ICMP "port unreachable" surfaces as
                    # WSAECONNRESET (10054) on the next socket operation.
                    latency_ms = (time.perf_counter() - start) * 1000.0
                    return CheckResult(
                        name=f"UDP {port} ({service})",
                        status=Status.FAILED,
                        message="Port unreachable (ICMP rejection received) - actively blocked/closed.",
                        details={"port": port, "target": resolved, "outcome": "icmp_unreachable"},
                        duration_ms=latency_ms,
                    )
        except OSError as exc:
            latency_ms = (time.perf_counter() - start) * 1000.0
            return CheckResult(
                name=f"UDP {port} ({service})",
                status=Status.FAILED,
                message=f"Socket error: {exc}",
                details={"port": port, "target": target},
                duration_ms=latency_ms,
            )

    def run_all(self) -> ModuleReport:
        report = ModuleReport(module_name="UDP Test")
        self._report(f"Probing {len(self.ports)} UDP ports ...")
        for port in self.ports:
            self._report(f"Probing UDP port {port} ...")
            report.add(self.probe_port(port))
        report.finish()
        return report
