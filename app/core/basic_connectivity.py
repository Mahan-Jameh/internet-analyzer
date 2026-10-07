"""
basic_connectivity.py
======================
The first, simplest layer of diagnostics: ping, traceroute, plain DNS
resolution and a plain HTTP/HTTPS request. This mirrors what a normal
user would try manually and gives the analyzer engine an early signal
of whether the machine has any Internet access at all.
"""

from __future__ import annotations

import re
import time
from typing import Callable, Optional

import requests

from app.constants import HTTP_TEST_URL_PLAIN, HTTP_TEST_URL_TLS, HTTP_TIMEOUT, PING_TIMEOUT
from app.logger import get_logger
from app.models import CheckResult, ModuleReport, Status
from app.utils.helpers import IS_WINDOWS, parse_ping_rtts, resolve_host, run_subprocess

log = get_logger(__name__)

ProgressCallback = Optional[Callable[[str], None]]


class BasicConnectivityTester:
    """Runs ping / traceroute / DNS / HTTP / HTTPS basic checks."""

    def __init__(self, target_host: str = "1.1.1.1", progress_cb: ProgressCallback = None) -> None:
        self.target_host = target_host
        self.progress_cb = progress_cb

    def _report(self, message: str) -> None:
        if self.progress_cb:
            self.progress_cb(message)
        log.info(message)

    def run_all(self) -> ModuleReport:
        report = ModuleReport(module_name="Basic Connectivity")

        report.add(self.ping(self.target_host))
        report.add(self.traceroute(self.target_host))
        report.add(self.dns_resolution("www.google.com"))
        report.add(self.http_request(HTTP_TEST_URL_PLAIN, label="HTTP Request"))
        report.add(self.http_request(HTTP_TEST_URL_TLS, label="HTTPS Request"))

        report.finish()
        return report

    # ------------------------------------------------------------------ #
    def ping(self, host: str, count: int = 4) -> CheckResult:
        self._report(f"Pinging {host} ...")
        start = time.perf_counter()

        if IS_WINDOWS:
            args = ["ping", "-n", str(count), "-w", str(int(PING_TIMEOUT * 1000)), host]
        else:
            args = ["ping", "-c", str(count), "-W", str(int(PING_TIMEOUT)), host]

        code, out, err = run_subprocess(args, timeout=PING_TIMEOUT * count + 5)
        duration_ms = (time.perf_counter() - start) * 1000.0

        rtts = parse_ping_rtts(out)
        sent = count
        received = len(rtts)
        loss_pct = 100.0 * (sent - received) / sent if sent else 100.0

        details = {
            "sent": sent,
            "received": received,
            "loss_percent": round(loss_pct, 1),
            "rtts_ms": rtts,
            "raw_output": out.strip() or err.strip(),
        }

        if received == 0:
            return CheckResult(
                name=f"Ping {host}",
                status=Status.FAILED,
                message="No reply received (100% packet loss or ICMP blocked).",
                details=details,
                duration_ms=duration_ms,
            )
        if loss_pct > 0:
            return CheckResult(
                name=f"Ping {host}",
                status=Status.WARNING,
                message=f"Partial packet loss: {loss_pct:.0f}% of packets lost.",
                details=details,
                duration_ms=duration_ms,
            )
        avg_rtt = sum(rtts) / len(rtts)
        return CheckResult(
            name=f"Ping {host}",
            status=Status.OK,
            message=f"Reachable, average RTT {avg_rtt:.1f} ms.",
            details=details,
            duration_ms=duration_ms,
        )

    # ------------------------------------------------------------------ #
    def traceroute(self, host: str, max_hops: int = 20) -> CheckResult:
        self._report(f"Tracing route to {host} ...")
        start = time.perf_counter()

        if IS_WINDOWS:
            args = ["tracert", "-d", "-h", str(max_hops), "-w", "1000", host]
        else:
            args = ["traceroute", "-n", "-m", str(max_hops), "-w", "1", host]

        code, out, err = run_subprocess(args, timeout=25)
        duration_ms = (time.perf_counter() - start) * 1000.0

        hops = re.findall(r"^\s*(\d+)\s", out, re.MULTILINE)

        details = {"hop_count": len(hops), "raw_output": out.strip() or err.strip()}

        if code not in (0, -1) and not out:
            return CheckResult(
                name=f"Traceroute {host}",
                status=Status.UNKNOWN,
                message="Traceroute could not be executed on this system.",
                details=details,
                duration_ms=duration_ms,
            )
        if not hops:
            return CheckResult(
                name=f"Traceroute {host}",
                status=Status.WARNING,
                message="No hops recorded - route may be filtered.",
                details=details,
                duration_ms=duration_ms,
            )
        return CheckResult(
            name=f"Traceroute {host}",
            status=Status.OK,
            message=f"Route traced through {len(hops)} hop(s).",
            details=details,
            duration_ms=duration_ms,
        )

    # ------------------------------------------------------------------ #
    def dns_resolution(self, hostname: str) -> CheckResult:
        self._report(f"Resolving {hostname} ...")
        start = time.perf_counter()
        addresses = resolve_host(hostname)
        duration_ms = (time.perf_counter() - start) * 1000.0

        if not addresses:
            return CheckResult(
                name=f"DNS Resolution ({hostname})",
                status=Status.FAILED,
                message="Name could not be resolved.",
                duration_ms=duration_ms,
            )
        return CheckResult(
            name=f"DNS Resolution ({hostname})",
            status=Status.OK,
            message=f"Resolved to: {', '.join(addresses[:4])}",
            details={"addresses": addresses},
            duration_ms=duration_ms,
        )

    # ------------------------------------------------------------------ #
    def http_request(self, url: str, label: str = "HTTP Request") -> CheckResult:
        self._report(f"Requesting {url} ...")
        start = time.perf_counter()
        try:
            resp = requests.get(url, timeout=HTTP_TIMEOUT, allow_redirects=True)
            duration_ms = (time.perf_counter() - start) * 1000.0
            details = {
                "status_code": resp.status_code,
                "final_url": resp.url,
                "elapsed_ms": round(duration_ms, 1),
            }
            if resp.status_code < 400:
                return CheckResult(
                    name=label,
                    status=Status.OK,
                    message=f"HTTP {resp.status_code} in {duration_ms:.0f} ms.",
                    details=details,
                    duration_ms=duration_ms,
                )
            return CheckResult(
                name=label,
                status=Status.WARNING,
                message=f"Server responded with HTTP {resp.status_code}.",
                details=details,
                duration_ms=duration_ms,
            )
        except requests.exceptions.Timeout:
            duration_ms = (time.perf_counter() - start) * 1000.0
            return CheckResult(
                name=label,
                status=Status.FAILED,
                message="Request timed out.",
                duration_ms=duration_ms,
            )
        except requests.exceptions.SSLError as exc:
            duration_ms = (time.perf_counter() - start) * 1000.0
            return CheckResult(
                name=label,
                status=Status.FAILED,
                message=f"TLS/SSL error: {exc}",
                duration_ms=duration_ms,
            )
        except requests.exceptions.ConnectionError as exc:
            duration_ms = (time.perf_counter() - start) * 1000.0
            return CheckResult(
                name=label,
                status=Status.FAILED,
                message=f"Connection failed: {exc}",
                duration_ms=duration_ms,
            )
        except requests.exceptions.RequestException as exc:
            duration_ms = (time.perf_counter() - start) * 1000.0
            return CheckResult(
                name=label,
                status=Status.FAILED,
                message=f"Request failed: {exc}",
                duration_ms=duration_ms,
            )
