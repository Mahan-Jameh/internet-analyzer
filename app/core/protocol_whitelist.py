"""
protocol_whitelist.py
=====================
OPT-IN probe for a "protocol whitelist" filter: a middlebox that only lets
recognisable DNS / HTTP / TLS traffic through on the standard ports and
silently drops anything else, judging only the first data packets.

Published research (Bock et al., FOCI 2020, on Iran's protocol filter) found
exactly that for ports 53, 80 and 443. Network behaviour changes over time,
so a result here is a hint about today's network, not a statement about the
past study.

Method: send the same small non-protocol payload to the SAME server on
  * port 443 (a monitored standard port), and
  * port 8443 (a control port that the server also speaks TLS on).
A server normally reacts to garbage by closing the connection or answering
with an error. If it does so on 8443 but stays completely silent on 443,
the payload was probably dropped on the way.

WARNING: a filter of this kind may drop the client's packets for a while
(about 60 seconds in the cited study) after seeing a violation. The GUI
asks for confirmation before this module is run.
"""

from __future__ import annotations

import socket
import ssl
import time
from typing import Callable, Optional

from app.constants import (
    PROTOCOL_PROBE_CONTROL_PORT,
    PROTOCOL_PROBE_HOST,
    PROTOCOL_PROBE_MONITORED_PORT,
    PROTOCOL_PROBE_PAYLOAD,
    PROTOCOL_PROBE_TIMEOUT,
)
from app.logger import get_logger
from app.models import CheckResult, ModuleReport, Status
from app.utils.helpers import resolve_host

log = get_logger(__name__)

ProgressCallback = Optional[Callable[[str], None]]

REACTED = {"closed", "reset", "response"}


def interpret_outcomes(monitored: str, control: str) -> str:
    """
    Pure decision logic.
    Returns: filtered_suspected / no_difference / inconclusive / unreachable
    """
    if "connect_failed" in (monitored, control):
        return "unreachable"
    if control not in REACTED:
        return "inconclusive"          # the control port stayed silent too
    if monitored == "silent":
        return "filtered_suspected"
    return "no_difference"


class ProtocolWhitelistProbe:
    def __init__(self, progress_cb: ProgressCallback = None) -> None:
        self.progress_cb = progress_cb

    def _report(self, message: str) -> None:
        if self.progress_cb:
            self.progress_cb(message)
        log.info(message)

    def _send_payload(self, ip: str, port: int) -> str:
        """Returns closed / reset / response / silent / connect_failed."""
        try:
            sock = socket.create_connection((ip, port), timeout=PROTOCOL_PROBE_TIMEOUT)
        except OSError:
            return "connect_failed"
        try:
            sock.settimeout(PROTOCOL_PROBE_TIMEOUT)
            sock.sendall(PROTOCOL_PROBE_PAYLOAD)
            try:
                data = sock.recv(2048)
                return "closed" if data == b"" else "response"
            except socket.timeout:
                return "silent"
            except ConnectionResetError:
                return "reset"
        except OSError:
            return "reset"
        finally:
            sock.close()

    def _baseline_tls_ok(self, ip: str) -> bool:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((ip, PROTOCOL_PROBE_MONITORED_PORT),
                                          timeout=PROTOCOL_PROBE_TIMEOUT) as raw:
                with context.wrap_socket(raw, server_hostname=PROTOCOL_PROBE_HOST):
                    return True
        except OSError:
            return False

    def run_all(self) -> ModuleReport:
        report = ModuleReport(module_name="Protocol Whitelist Probe")
        report.add(self._run_check())
        report.finish()
        return report

    def _run_check(self) -> CheckResult:
        name = "Protocol Whitelist Probe"
        start = time.perf_counter()
        ips = resolve_host(PROTOCOL_PROBE_HOST, family=socket.AF_INET)
        if not ips:
            return CheckResult(name=name, status=Status.UNKNOWN,
                               message="The probe server could not be resolved.")
        ip = ips[0]

        self._report("Baseline TLS handshake before the protocol probe ...")
        if not self._baseline_tls_ok(ip):
            return CheckResult(
                name=name, status=Status.UNKNOWN,
                message="A normal TLS handshake to the probe server failed first, so the "
                        "probe would not be meaningful.")

        self._report("Sending a non-protocol payload to the control port ...")
        control = self._send_payload(ip, PROTOCOL_PROBE_CONTROL_PORT)
        self._report("Sending a non-protocol payload to the monitored port ...")
        monitored = self._send_payload(ip, PROTOCOL_PROBE_MONITORED_PORT)
        duration_ms = (time.perf_counter() - start) * 1000.0

        verdict = interpret_outcomes(monitored, control)
        details = {"server_ip": ip, "monitored_port": PROTOCOL_PROBE_MONITORED_PORT,
                   "monitored_outcome": monitored, "control_port": PROTOCOL_PROBE_CONTROL_PORT,
                   "control_outcome": control, "verdict": verdict,
                   "suspected": verdict == "filtered_suspected"}

        messages = {
            "filtered_suspected": (
                Status.WARNING,
                "The server reacted to the odd payload on the control port but stayed silent on "
                "port 443. That matches a filter that drops non-standard traffic on port 443, "
                "though a server quirk could cause the same result."),
            "no_difference": (
                Status.OK,
                "Port 443 reacted to the odd payload like the control port did; no sign of a "
                "protocol whitelist."),
            "inconclusive": (
                Status.UNKNOWN,
                "The control port did not react either, so the two cannot be compared."),
            "unreachable": (
                Status.UNKNOWN,
                "One of the two ports could not be reached, so the probe is inconclusive."),
        }
        status, message = messages[verdict]
        return CheckResult(name=name, status=status, message=message,
                           details=details, duration_ms=duration_ms)
