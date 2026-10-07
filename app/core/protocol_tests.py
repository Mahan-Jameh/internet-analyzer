"""
protocol_tests.py
==================
Focused tests for individual protocols that don't fit neatly into the
DNS / TCP / UDP / TLS / HTTP modules: QUIC reachability, DNS-over-HTTPS,
DNS-over-TLS, ICMP, and WebSocket.
"""

from __future__ import annotations

import asyncio
import socket
import ssl
import threading
import time
from typing import Any, Callable, Optional

import httpx

from app.constants import (
    DOH_ENDPOINTS,
    DOT_PORT,
    DOT_SERVERS,
    WEBSOCKET_TEST_URL,
)
from app.core.icmp import ping_result
from app.diag.adapter import check_from_result
from app.diag.neterrors import normalize_exception, normalize_wrapped_exception
from app.diag.results import Severity, TechnicalStatus, TestResult
from app.diag.testconfig import DEFAULT_CONFIG, NetworkTestConfig
from app.logger import get_logger
from app.models import CheckResult, ModuleReport

log = get_logger(__name__)
_S = TechnicalStatus

ProgressCallback = Optional[Callable[[str], None]]

# A raw QUIC "Initial" packet is complex to build correctly; instead we send a
# plausible-length UDP payload to port 443. A reply proves UDP/443 passes; an ICMP
# rejection proves a closed port; SILENCE proves nothing (a real QUIC server
# also ignores malformed packets), so it is reported as "open or filtered".
_QUIC_PROBE_PAYLOAD = bytes(64)
_QUIC_TARGET = "1.1.1.1"


class ProtocolTester:
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
        report = ModuleReport(module_name="Protocol Tests")
        steps: list[tuple[str, Callable[[], CheckResult]]] = [("QUIC Transport Reachability", self._quic_reachability)]
        steps += [(f"DNS-over-HTTPS ({n})", lambda n=n, e=e: self._doh(n, e)) for n, e in DOH_ENDPOINTS.items()]
        steps += [(f"DNS-over-TLS ({n})", lambda n=n, sv=sv: self._dot(n, sv)) for n, sv in DOT_SERVERS.items()]
        steps += [("ICMP Echo", self._icmp), ("WebSocket (wss://)", self._websocket)]
        for name, func in steps:
            if self.cancel.is_set():
                break
            try:
                check = func()
            except Exception as exc:  # noqa: BLE001 - one probe must never break the module
                log.exception("Protocol step %s crashed", name)
                res = TestResult(f"protocol.{name}", "protocol", status=_S.ERROR, error_type=type(exc).__name__,
                                 error_message=str(exc)[:200], summary=f"{name} could not be completed.")
                check = check_from_result(name, res)
            report.add(check)
            if isinstance(check.result, TestResult):
                report.results.append(check.result)
        report.finish()
        return report

    # ------------------------------------------------------------------ #
    def _fill_error(self, res: TestResult, exc: BaseException, wrapped: bool = False) -> None:
        norm = normalize_wrapped_exception(exc) if wrapped else normalize_exception(exc)
        res.status = norm.status
        res.error_type, res.error_code = norm.error_type, norm.error_code
        res.error_message, res.platform_error, res.recoverable = norm.error_message, norm.platform_error, norm.recoverable

    # ------------------------------------------------------------------ #
    def _quic_reachability(self) -> CheckResult:
        self._report("Checking UDP/443 (QUIC transport) reachability ...")
        timeout = self.config.udp_timeout
        res = TestResult("protocol.quic_udp443", "udp", target=_QUIC_TARGET, resolved_ip=_QUIC_TARGET,
                         address_family="IPv4", protocol="UDP", port=443, timeout_ms=int(timeout * 1000),
                         metadata={"role": "quic_transport"})
        start = time.perf_counter()
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(timeout)
                sock.connect((_QUIC_TARGET, 443))       # connected: Windows reports ICMP errors on recv
                sock.send(_QUIC_PROBE_PAYLOAD)
                try:
                    sock.recv(2048)
                    res.status = _S.SUCCESS
                    res.summary = "Received a UDP response on port 443."
                    res.add_evidence("A UDP datagram came back from port 443")
                except (socket.timeout, TimeoutError):
                    res.status, res.severity = _S.OPEN_OR_FILTERED, Severity.INFO
                    res.interpretation, res.confidence = "UDP_443_NO_REPLY", 0.3
                    res.summary = ("No UDP/443 reply. A QUIC server ignores malformed packets, so this "
                                   "alone does not show that QUIC is blocked (see the HTTP/3 test).")
                    res.add_evidence("No reply and no ICMP error within the timeout")
                except ConnectionResetError as exc:
                    self._fill_error(res, exc)
                    res.status, res.severity = _S.CLOSED, Severity.WARNING
                    res.summary = "UDP/443 was rejected with an ICMP port-unreachable message."
                    res.add_evidence("ICMP port unreachable was reported for UDP/443")
        except OSError as exc:
            self._fill_error(res, exc)
            res.summary = f"UDP/443 could not be probed: {res.error_code}."
        res.duration_ms = (time.perf_counter() - start) * 1000.0
        return check_from_result("QUIC Transport Reachability", res)

    # ------------------------------------------------------------------ #
    def _doh(self, name: str, endpoint: str) -> CheckResult:
        self._report(f"Testing DNS-over-HTTPS via {name} ...")
        timeout = self.config.read_timeout
        res = TestResult(f"protocol.doh.{name}", "doh", target=endpoint.split("/")[2], protocol="HTTPS",
                         port=443, timeout_ms=int(timeout * 1000), metadata={"role": "doh", "provider": name})
        start = time.perf_counter()
        try:
            resp = httpx.get(endpoint, params={"name": "cloudflare.com", "type": "A"},
                             headers={"accept": "application/dns-json"}, timeout=timeout)
            res.duration_ms = (time.perf_counter() - start) * 1000.0
            res.metrics["http_status"] = resp.status_code
            if resp.status_code == 200:
                res.status = _S.SUCCESS
                res.summary = f"DoH query succeeded in {res.duration_ms:.0f} ms."
            else:
                res.status, res.error_code = _S.HTTP_FAILED, f"HTTP_{resp.status_code}"
                res.severity = Severity.WARNING
                res.summary = f"DoH endpoint returned HTTP {resp.status_code}."
        except httpx.HTTPError as exc:
            res.duration_ms = (time.perf_counter() - start) * 1000.0
            self._fill_error(res, exc, wrapped=True)
            res.summary = f"DoH request failed ({res.error_code})."
        return check_from_result(f"DNS-over-HTTPS ({name})", res)

    # ------------------------------------------------------------------ #
    def _dot(self, name: str, server: str) -> CheckResult:
        self._report(f"Testing DNS-over-TLS via {name} ...")
        timeout = self.config.tls_timeout
        res = TestResult(f"protocol.dot.{name}", "dot", target=server, resolved_ip=server,
                         address_family="IPv4", protocol="TLS", port=DOT_PORT, timeout_ms=int(timeout * 1000),
                         metadata={"role": "dot", "provider": name})
        start = time.perf_counter()
        try:
            context = ssl.create_default_context()
            with socket.create_connection((server, DOT_PORT), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=server) as tls_sock:
                    # Minimal DNS-over-TLS query: 2-byte length prefix + DNS query.
                    query = (b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
                             b"\x0acloudflare\x03com\x00\x00\x01\x00\x01")
                    tls_sock.send(len(query).to_bytes(2, "big") + query)
                    response = tls_sock.recv(2048)
            res.duration_ms = (time.perf_counter() - start) * 1000.0
            if response:
                res.status = _S.SUCCESS
                res.summary = f"DoT query succeeded in {res.duration_ms:.0f} ms."
            else:
                res.status, res.severity = _S.PARTIAL, Severity.WARNING
                res.summary = "TLS handshake succeeded but no DNS response was returned."
        except (OSError, ssl.SSLError) as exc:
            res.duration_ms = (time.perf_counter() - start) * 1000.0
            self._fill_error(res, exc)
            res.summary = f"DoT failed ({res.error_code})."
        return check_from_result(f"DNS-over-TLS ({name})", res)

    # ------------------------------------------------------------------ #
    def _icmp(self) -> CheckResult:
        self._report("Testing ICMP echo ...")
        res = ping_result("1.1.1.1", 2, self.config, test_id="protocol.icmp", role="icmp_semantics")
        if res.ok:
            res.summary = "ICMP echo replies received - ICMP is not blocked on this path."
        else:
            # ICMP silence is not "no Internet": many hosts and firewalls drop echo requests.
            res.severity = Severity.INFO if res.status is _S.TIMEOUT else res.severity
        return check_from_result("ICMP Echo", res)

    # ------------------------------------------------------------------ #
    def _websocket(self) -> CheckResult:
        self._report("Testing WebSocket (wss://) handshake ...")
        res = TestResult("protocol.websocket", "websocket", target=WEBSOCKET_TEST_URL.split("/")[2],
                         protocol="WebSocket", port=443, timeout_ms=8000, metadata={"role": "websocket"})
        start = time.perf_counter()
        try:
            success, message = asyncio.run(asyncio.wait_for(self._websocket_probe(), timeout=8))
            res.status = _S.SUCCESS if success else _S.PARTIAL
            res.summary = message
        except ImportError:
            res.status, res.severity, res.error_code = _S.NOT_APPLICABLE, Severity.INFO, "MODULE_MISSING"
            res.summary = "The optional 'websockets' package is not installed."
        except (asyncio.TimeoutError, TimeoutError) as exc:
            self._fill_error(res, exc)
            res.status, res.error_code = _S.TIMEOUT, "TIMEOUT"
            res.summary = "WebSocket handshake timed out."
        except Exception as exc:  # noqa: BLE001
            self._fill_error(res, exc, wrapped=True)
            res.summary = f"WebSocket handshake failed ({res.error_code})."
        res.duration_ms = (time.perf_counter() - start) * 1000.0
        return check_from_result("WebSocket (wss://)", res)

    async def _websocket_probe(self) -> tuple[bool, str]:
        import websockets

        async with websockets.connect(WEBSOCKET_TEST_URL, open_timeout=6) as ws:
            await ws.send("ping")
            await ws.recv()
            return True, "WebSocket handshake and echo round-trip succeeded."
