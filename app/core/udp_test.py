"""
udp_test.py
===========
UDP is connectionless, so "is the port open?" cannot be answered like it is for
TCP. The semantics used here:

    reply received ................ OPEN          (the service answered)
    ICMP port unreachable ......... CLOSED        (host reachable, nothing listens)
    network/host unreachable ...... UNREACHABLE
    silence, protocol-aware probe . OPEN_OR_FILTERED
    silence, generic probe ........ INCONCLUSIVE  (we could not have expected an answer)

Ports 53 (DNS) and 123 (NTP) are probed with real protocol requests and the
reply is validated. For every other port no valid protocol exchange is
implemented, so silence is reported as INCONCLUSIVE rather than invented
certainty. A *connected* UDP socket is used: that is what makes the operating
system - including Windows, which reports it as WSAECONNRESET - surface the
ICMP "port unreachable" message.
"""

from __future__ import annotations

import os
import socket
import struct
import threading
import time
from typing import Callable, Optional

from app.constants import ALLOWED_UDP_PORTS, UDP_PORT_NAMES
from app.diag.adapter import check_from_result
from app.diag.neterrors import normalize_exception
from app.diag.probes import dns_failure_result, family_of_ip, resolve
from app.diag.results import RetryOutcome, TechnicalStatus, TestResult
from app.diag.retry import run_with_retry
from app.diag.testconfig import DEFAULT_CONFIG, NetworkTestConfig
from app.logger import get_logger
from app.models import ModuleReport

log = get_logger(__name__)
_S = TechnicalStatus

ProgressCallback = Optional[Callable[[str], None]]

# Per-port default targets. Only 53 and 123 have a service that is expected to answer
# from a public address; for the other ports the user should supply a real target.
DEFAULT_TARGETS = {
    53: "1.1.1.1", 123: "time.cloudflare.com", 443: "1.1.1.1",
    500: "8.8.8.8", 4500: "8.8.8.8", 51820: "8.8.8.8",
}
PROTOCOL_AWARE_PORTS = (53, 123)

_DEFAULT_PROBE = b"ICPA-DIAGNOSTIC-PROBE"
_NTP_PROBE = b"\x1b" + 47 * b"\0"          # SNTP client request (RFC 4330)


def build_dns_query(txid: int | None = None) -> tuple[bytes, int]:
    """A minimal, valid 'example.com A' query; returns (packet, transaction id)."""
    tid = txid if txid is not None else struct.unpack(">H", os.urandom(2))[0]
    packet = (struct.pack(">H", tid) + b"\x01\x00" + b"\x00\x01\x00\x00\x00\x00\x00\x00"
              + b"\x07example\x03com\x00" + b"\x00\x01\x00\x01")
    return packet, tid


def validate_dns_reply(data: bytes, txid: int) -> bool:
    """True if the datagram looks like a DNS response to *our* query."""
    return len(data) >= 12 and struct.unpack(">H", data[:2])[0] == txid and bool(data[2] & 0x80)


def validate_ntp_reply(data: bytes) -> bool:
    """True for an NTP server-mode reply (mode 4) of full length."""
    return len(data) >= 48 and (data[0] & 0x07) in (4, 5)


class UDPTester:
    def __init__(
        self,
        target_host: Optional[str] = None,
        ports: Optional[list[int]] = None,
        progress_cb: ProgressCallback = None,
        config: NetworkTestConfig = DEFAULT_CONFIG,
        cancel: Optional[threading.Event] = None,
    ) -> None:
        self.target_host_override = target_host
        requested = ports or ALLOWED_UDP_PORTS
        self.ports = [p for p in requested if p in ALLOWED_UDP_PORTS]
        self.progress_cb = progress_cb
        self.config = config
        self.cancel = cancel or threading.Event()

    def _report(self, message: str) -> None:
        if self.progress_cb:
            self.progress_cb(message)
        log.info(message)

    # -- one probe --------------------------------------------------------
    def _payload(self, port: int) -> tuple[bytes, Callable[[bytes], bool] | None, str]:
        if port == 53:
            packet, tid = build_dns_query()
            return packet, lambda d: validate_dns_reply(d, tid), "dns-query"
        if port == 123:
            return _NTP_PROBE, validate_ntp_reply, "ntp-request"
        return _DEFAULT_PROBE, None, "generic"

    def _attempt(self, target: str, ip: str, port: int, attempt: int) -> TestResult:
        service = UDP_PORT_NAMES.get(port, "Unknown")
        payload, validator, probe_kind = self._payload(port)
        timeout = self.config.udp_timeout
        res = TestResult(
            f"udp.{target}.{port}", "udp", target=target, resolved_ip=ip, address_family=family_of_ip(ip),
            protocol="UDP", port=port, timeout_ms=int(timeout * 1000),
            metadata={"service": service, "probe": probe_kind, "protocol_aware": validator is not None,
                      "attempt": attempt},
        )
        start = time.perf_counter()
        af = socket.AF_INET6 if ":" in ip else socket.AF_INET
        try:
            with socket.socket(af, socket.SOCK_DGRAM) as sock:
                sock.settimeout(timeout)
                sock.connect((ip, port))             # connected socket: OS reports ICMP errors
                sock.send(payload)
                data = sock.recv(2048)
                res.duration_ms = (time.perf_counter() - start) * 1000.0
                res.metrics["response_bytes"] = len(data)
                if validator is None or validator(data):
                    res.status = _S.OPEN
                    res.summary = f"UDP {port}: a reply of {len(data)} bytes arrived in {res.duration_ms:.0f} ms."
                    res.add_evidence(f"Received {len(data)} bytes from {ip}:{port}")
                else:
                    res.status = _S.OPEN
                    res.warnings.append("A reply arrived but it did not look like the expected protocol answer.")
                    res.summary = f"UDP {port}: something replied, but not with a valid {service} answer."
                    res.confidence = 0.5
                return res
        except (socket.timeout, TimeoutError):
            res.duration_ms = (time.perf_counter() - start) * 1000.0
            if validator is not None:
                res.status, res.interpretation, res.confidence = _S.OPEN_OR_FILTERED, "NO_RESPONSE", 0.4
                res.summary = (f"UDP {port}: no reply to a real {service} request within "
                               f"{timeout:.1f} s; the packet or the reply may have been dropped.")
            else:
                res.status, res.interpretation = _S.INCONCLUSIVE, "NO_PROTOCOL_AWARE_PROBE"
                res.summary = (f"UDP {port}: no reply, which is inconclusive - this tool has no valid "
                               f"{service} exchange, so silence proves nothing.")
            res.error_code = "NO_RESPONSE" if validator is not None else "NO_PROTOCOL_AWARE_PROBE"
            res.add_evidence("No datagram and no ICMP error were received.")
            return res
        except OSError as exc:
            res.duration_ms = (time.perf_counter() - start) * 1000.0
            err = normalize_exception(exc)
            res.error_type, res.error_code = err.error_type, err.error_code
            res.platform_error, res.error_message = err.platform_error, err.error_message
            # ICMP "port unreachable": ECONNREFUSED on Linux/macOS, WSAECONNRESET on Windows
            if err.error_code in ("CONNECTION_REFUSED", "CONNECTION_RESET"):
                res.status, res.interpretation, res.confidence = _S.CLOSED, "ICMP_PORT_UNREACHABLE", 0.85
                res.error_code = "ICMP_PORT_UNREACHABLE"
                res.summary = f"UDP {port}: ICMP port unreachable - the host is reachable but nothing listens here."
                res.add_evidence("The OS reported an ICMP port-unreachable message for this socket.")
            elif err.status is _S.UNREACHABLE:
                res.status = _S.UNREACHABLE
                res.summary = f"UDP {port}: {err.error_message}."
            else:
                res.status = _S.ERROR
                res.summary = f"UDP {port}: socket error ({err.error_message})."
            return res

    def probe_port(self, port: int) -> TestResult:
        target = self.target_host_override or DEFAULT_TARGETS.get(port, "1.1.1.1")
        resolution = resolve(target)
        if not resolution.ok:
            return dns_failure_result(f"dns.{target}", target, resolution)
        ip = resolution.ip or ""
        result = run_with_retry(lambda n: self._attempt(target, ip, port, n), self.config.retry, self.cancel)
        # Silence is retried once for protocol-aware probes: UDP packets are lost more often.
        return result

    def run_all(self) -> ModuleReport:
        report = ModuleReport(module_name="UDP Test")
        self._report(f"Probing {len(self.ports)} UDP ports ...")
        for port in self.ports:
            if self.cancel.is_set():
                break
            self._report(f"Probing UDP port {port} ...")
            service = UDP_PORT_NAMES.get(port, "Unknown")
            res = self.probe_port(port)
            details = {"port": port, "target": res.resolved_ip or res.target,
                       "outcome": (res.interpretation or res.status.value).lower()}
            if "response_bytes" in res.metrics:
                details["response_bytes"] = res.metrics["response_bytes"]
            report.add(check_from_result(f"UDP {port} ({service})", res, details=details))
        report.finish()
        return report
