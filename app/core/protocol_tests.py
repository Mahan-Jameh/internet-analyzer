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
import time
from typing import Callable, Optional

import httpx

from app.constants import (
    DOH_ENDPOINTS,
    DOT_PORT,
    DOT_SERVERS,
    HTTP_TIMEOUT,
    PING_TIMEOUT,
    TLS_TIMEOUT,
    UDP_TIMEOUT,
    WEBSOCKET_TEST_URL,
)
from app.logger import get_logger
from app.models import CheckResult, ModuleReport, Status
from app.utils.helpers import IS_WINDOWS, parse_ping_rtts, run_subprocess

log = get_logger(__name__)

ProgressCallback = Optional[Callable[[str], None]]

# A raw QUIC "Initial" packet is complex to build correctly; instead we
# send a plausible-length random UDP payload to port 443 and check whether
# we get *any* response or an explicit ICMP rejection, which is enough to
# tell "UDP/443 appears open" from "UDP/443 appears blocked".
_QUIC_PROBE_PAYLOAD = bytes(64)


class ProtocolTester:
    def __init__(self, progress_cb: ProgressCallback = None) -> None:
        self.progress_cb = progress_cb

    def _report(self, message: str) -> None:
        if self.progress_cb:
            self.progress_cb(message)
        log.info(message)

    def run_all(self) -> ModuleReport:
        report = ModuleReport(module_name="Protocol Tests")

        report.add(self._quic_reachability())
        for name, endpoint in DOH_ENDPOINTS.items():
            report.add(self._doh(name, endpoint))
        for name, server in DOT_SERVERS.items():
            report.add(self._dot(name, server))
        report.add(self._icmp())
        report.add(self._websocket())

        report.finish()
        return report

    # ------------------------------------------------------------------ #
    def _quic_reachability(self) -> CheckResult:
        self._report("Checking UDP/443 (QUIC transport) reachability ...")
        start = time.perf_counter()
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(UDP_TIMEOUT)
                sock.sendto(_QUIC_PROBE_PAYLOAD, ("1.1.1.1", 443))
                try:
                    sock.recvfrom(2048)
                    duration_ms = (time.perf_counter() - start) * 1000.0
                    return CheckResult(
                        name="QUIC Transport Reachability",
                        status=Status.OK,
                        message=f"Received a UDP response on port 443 in {duration_ms:.0f} ms.",
                        duration_ms=duration_ms,
                    )
                except socket.timeout:
                    duration_ms = (time.perf_counter() - start) * 1000.0
                    return CheckResult(
                        name="QUIC Transport Reachability",
                        status=Status.WARNING,
                        message="No UDP/443 response (see HTTP Test module for a full QUIC "
                        "handshake result, which is more conclusive).",
                        duration_ms=duration_ms,
                    )
                except ConnectionResetError:
                    duration_ms = (time.perf_counter() - start) * 1000.0
                    return CheckResult(
                        name="QUIC Transport Reachability",
                        status=Status.FAILED,
                        message="UDP/443 rejected with ICMP port-unreachable.",
                        duration_ms=duration_ms,
                    )
        except OSError as exc:
            return CheckResult(
                name="QUIC Transport Reachability",
                status=Status.FAILED,
                message=f"Socket error: {exc}",
            )

    # ------------------------------------------------------------------ #
    def _doh(self, name: str, endpoint: str) -> CheckResult:
        self._report(f"Testing DNS-over-HTTPS via {name} ...")
        start = time.perf_counter()
        try:
            resp = httpx.get(
                endpoint,
                params={"name": "cloudflare.com", "type": "A"},
                headers={"accept": "application/dns-json"},
                timeout=HTTP_TIMEOUT,
            )
            duration_ms = (time.perf_counter() - start) * 1000.0
            if resp.status_code == 200:
                return CheckResult(
                    name=f"DNS-over-HTTPS ({name})",
                    status=Status.OK,
                    message=f"DoH query succeeded in {duration_ms:.0f} ms.",
                    duration_ms=duration_ms,
                )
            return CheckResult(
                name=f"DNS-over-HTTPS ({name})",
                status=Status.WARNING,
                message=f"DoH endpoint returned HTTP {resp.status_code}.",
                duration_ms=duration_ms,
            )
        except httpx.HTTPError as exc:
            duration_ms = (time.perf_counter() - start) * 1000.0
            return CheckResult(
                name=f"DNS-over-HTTPS ({name})",
                status=Status.FAILED,
                message=f"DoH request failed: {exc}",
                duration_ms=duration_ms,
            )

    # ------------------------------------------------------------------ #
    def _dot(self, name: str, server: str) -> CheckResult:
        self._report(f"Testing DNS-over-TLS via {name} ...")
        start = time.perf_counter()
        try:
            context = ssl.create_default_context()
            with socket.create_connection((server, DOT_PORT), timeout=TLS_TIMEOUT) as sock:
                with context.wrap_socket(sock, server_hostname=server) as tls_sock:
                    # Minimal DNS-over-TLS query: 2-byte length prefix + DNS query.
                    query = (
                        b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
                        b"\x0acloudflare\x03com\x00\x00\x01\x00\x01"
                    )
                    tls_sock.send(len(query).to_bytes(2, "big") + query)
                    response = tls_sock.recv(2048)
            duration_ms = (time.perf_counter() - start) * 1000.0
            if response:
                return CheckResult(
                    name=f"DNS-over-TLS ({name})",
                    status=Status.OK,
                    message=f"DoT query succeeded in {duration_ms:.0f} ms.",
                    duration_ms=duration_ms,
                )
            return CheckResult(
                name=f"DNS-over-TLS ({name})",
                status=Status.WARNING,
                message="TLS handshake succeeded but no DNS response was returned.",
                duration_ms=duration_ms,
            )
        except (OSError, ssl.SSLError) as exc:
            duration_ms = (time.perf_counter() - start) * 1000.0
            return CheckResult(
                name=f"DNS-over-TLS ({name})",
                status=Status.FAILED,
                message=f"DoT failed: {exc}",
                duration_ms=duration_ms,
            )

    # ------------------------------------------------------------------ #
    def _icmp(self) -> CheckResult:
        self._report("Testing ICMP echo ...")
        start = time.perf_counter()
        if IS_WINDOWS:
            args = ["ping", "-n", "2", "-w", str(int(PING_TIMEOUT * 1000)), "1.1.1.1"]
        else:
            args = ["ping", "-c", "2", "-W", str(int(PING_TIMEOUT)), "1.1.1.1"]
        code, out, err = run_subprocess(args, timeout=10)
        duration_ms = (time.perf_counter() - start) * 1000.0

        if parse_ping_rtts(out):
            return CheckResult(
                name="ICMP Echo",
                status=Status.OK,
                message="ICMP echo replies received - ICMP is not blocked.",
                duration_ms=duration_ms,
            )
        return CheckResult(
            name="ICMP Echo",
            status=Status.WARNING,
            message="No ICMP echo replies - ICMP may be blocked or rate limited on this path.",
            duration_ms=duration_ms,
        )

    # ------------------------------------------------------------------ #
    def _websocket(self) -> CheckResult:
        self._report("Testing WebSocket (wss://) handshake ...")
        start = time.perf_counter()
        try:
            success, message = asyncio.run(asyncio.wait_for(self._websocket_probe(), timeout=8))
            duration_ms = (time.perf_counter() - start) * 1000.0
            return CheckResult(
                name="WebSocket (wss://)",
                status=Status.OK if success else Status.WARNING,
                message=message,
                duration_ms=duration_ms,
            )
        except ImportError:
            return CheckResult(
                name="WebSocket (wss://)",
                status=Status.UNKNOWN,
                message="The optional 'websockets' package is not installed.",
            )
        except asyncio.TimeoutError:
            duration_ms = (time.perf_counter() - start) * 1000.0
            return CheckResult(
                name="WebSocket (wss://)",
                status=Status.FAILED,
                message="WebSocket handshake timed out.",
                duration_ms=duration_ms,
            )
        except Exception as exc:  # noqa: BLE001
            duration_ms = (time.perf_counter() - start) * 1000.0
            return CheckResult(
                name="WebSocket (wss://)",
                status=Status.FAILED,
                message=f"WebSocket handshake failed: {exc}",
                duration_ms=duration_ms,
            )

    async def _websocket_probe(self) -> tuple[bool, str]:
        import websockets

        async with websockets.connect(WEBSOCKET_TEST_URL, open_timeout=6) as ws:
            await ws.send("ping")
            await ws.recv()
            return True, "WebSocket handshake and echo round-trip succeeded."
