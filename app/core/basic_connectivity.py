"""
basic_connectivity.py
======================
The first, simplest layer of diagnostics: ping, traceroute, plain DNS resolution
and a plain HTTP/HTTPS request - what a normal user would try by hand.

Each check is reported as its own normalized signal. Ping is deliberately *not*
treated as proof of Internet availability in either direction (see
:mod:`app.core.icmp`).
"""

from __future__ import annotations

import re
import threading
import time
from typing import Callable, Optional

import requests

from app.constants import HTTP_TEST_URL_PLAIN, HTTP_TEST_URL_TLS
from app.core.icmp import ping_result
from app.diag.adapter import check_from_result
from app.diag.neterrors import normalize_wrapped_exception
from app.diag.probes import dns_failure_result, is_ip_literal, resolve
from app.diag.results import Severity, TechnicalStatus, TestResult
from app.diag.testconfig import DEFAULT_CONFIG, NetworkTestConfig
from app.logger import get_logger
from app.models import CheckResult, ModuleReport, Status
from app.utils.helpers import IS_WINDOWS, run_subprocess

log = get_logger(__name__)
_S = TechnicalStatus

ProgressCallback = Optional[Callable[[str], None]]

BLOCK_STATUS = 451


def http_result_from_response(test_id: str, url: str, status_code: int, final_url: str, elapsed_ms: float,
                              timeout_ms: int) -> TestResult:
    """Normalize an HTTP response (no exception) into a TestResult."""
    res = TestResult(test_id, "http", target=url, protocol="HTTPS" if url.startswith("https") else "HTTP",
                     duration_ms=elapsed_ms, timeout_ms=timeout_ms,
                     metrics={"status_code": status_code, "final_url": final_url},
                     metadata={"role": "basic", "final_url": final_url})
    if status_code == BLOCK_STATUS:
        res.status, res.error_code = _S.BLOCKED, "HTTP_451"
        res.summary = "The server answered HTTP 451 (unavailable for legal reasons)."
    elif status_code < 400:
        res.status = _S.SUCCESS
        res.summary = f"HTTP {status_code} in {elapsed_ms:.0f} ms."
    else:
        # The network path works (we got an answer); the *server* refused or failed.
        res.status, res.severity, res.error_code = _S.HTTP_FAILED, Severity.WARNING, f"HTTP_{status_code}"
        res.summary = f"Server responded with HTTP {status_code}."
    res.add_evidence(f"HTTP response {status_code} received from {final_url}")
    return res


def http_result_from_exception(test_id: str, url: str, exc: BaseException, elapsed_ms: float,
                               timeout_ms: int) -> TestResult:
    err = normalize_wrapped_exception(exc)
    res = TestResult(test_id, "http", target=url, protocol="HTTPS" if url.startswith("https") else "HTTP",
                     status=err.status, duration_ms=elapsed_ms, timeout_ms=timeout_ms,
                     error_type=err.error_type, error_code=err.error_code, platform_error=err.platform_error,
                     error_message=err.error_message[:200], recoverable=err.recoverable,
                     metadata={"role": "basic"})
    if err.status is _S.CLOSED:                      # refused connection: report as a connection failure
        res.status = _S.HTTP_FAILED
    elif err.status is _S.ERROR:
        res.status = _S.HTTP_FAILED
    res.summary = {
        "TIMEOUT": "Request timed out.",
        "CERTIFICATE_ERROR": f"Certificate problem: {err.error_message}",
        "TLS_PROTOCOL_ERROR": f"TLS error: {err.error_message}",
        "HOST_NOT_FOUND": "The name could not be resolved.",
        "CONNECTION_REFUSED": "The connection was refused.",
        "CONNECTION_RESET": "The connection was reset.",
    }.get(err.error_code, f"Request failed: {err.error_message}")
    res.add_evidence(f"{err.error_type}: {err.error_code}")
    return res


class BasicConnectivityTester:
    """Runs ping / traceroute / DNS / HTTP / HTTPS basic checks."""

    def __init__(self, target_host: str = "1.1.1.1", progress_cb: ProgressCallback = None,
                 config: NetworkTestConfig = DEFAULT_CONFIG, cancel: Optional[threading.Event] = None) -> None:
        self.target_host = target_host
        self.progress_cb = progress_cb
        self.config = config
        self.cancel = cancel or threading.Event()

    def _report(self, message: str) -> None:
        if self.progress_cb:
            self.progress_cb(message)
        log.info(message)

    def run_all(self) -> ModuleReport:
        report = ModuleReport(module_name="Basic Connectivity")
        steps = (
            lambda: self.ping(self.target_host),
            lambda: self.traceroute(self.target_host),
            lambda: self.dns_resolution("www.google.com"),
            lambda: self.http_request(HTTP_TEST_URL_PLAIN, label="HTTP Request"),
            lambda: self.http_request(HTTP_TEST_URL_TLS, label="HTTPS Request"),
        )
        for step in steps:
            if self.cancel.is_set():
                break
            report.add(step())
        report.finish()
        return report

    # ------------------------------------------------------------------ #
    def ping(self, host: str, count: int = 4) -> CheckResult:
        self._report(f"Pinging {host} ...")
        res = ping_result(host, count, self.config)
        m = res.metrics
        details = {"sent": m["packets_sent"], "received": m["packets_received"],
                   "loss_percent": m["packet_loss_percent"], "rtts_ms": [],
                   "raw_output": res.metadata.get("raw_output", "")}
        return check_from_result(f"Ping {host}", res, details=details)

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
        res = TestResult(f"traceroute.{host}", "traceroute", target=host, protocol="ICMP/UDP",
                         duration_ms=duration_ms, severity=Severity.INFO,
                         metrics={"hop_count": len(hops)}, metadata={"raw_output": (out.strip() or err.strip())[-3000:]})
        if code not in (0, -1) and not out:
            res.status, res.error_code = _S.ERROR, "NO_TRACE_COMMAND"
            res.summary = "Traceroute could not be executed on this system."
        elif not hops:
            res.status, res.interpretation = _S.INCONCLUSIVE, "ROUTE_FILTERED_OR_NO_REPLY"
            res.summary = "No hops recorded - the route may be filtered."
        else:
            res.status = _S.SUCCESS
            res.summary = f"Route traced through {len(hops)} hop(s)."
        details = {"hop_count": len(hops), "raw_output": res.metadata["raw_output"]}
        check = check_from_result(f"Traceroute {host}", res, details=details)
        # Traceroute is informational: a missing command is UNKNOWN, a silent route a WARNING (as before).
        check.status = Status.UNKNOWN if res.status is _S.ERROR else (
            Status.WARNING if res.status is _S.INCONCLUSIVE else Status.OK)
        return check

    # ------------------------------------------------------------------ #
    def dns_resolution(self, hostname: str) -> CheckResult:
        self._report(f"Resolving {hostname} ...")
        resolution = resolve(hostname)
        if not resolution.ok:
            res = dns_failure_result(f"dns.system.{hostname}", hostname, resolution,
                                     timeout_ms=int(self.config.dns_timeout * 1000))
            return check_from_result(f"DNS Resolution ({hostname})", res, message="Name could not be resolved.")
        res = TestResult(f"dns.system.{hostname}", "dns_resolution", target=hostname, resolved_ip=resolution.ip,
                         address_family=resolution.family, protocol="DNS", status=_S.SUCCESS,
                         duration_ms=resolution.duration_ms,
                         metadata={"role": "system", "domain": hostname, "addresses": resolution.all_ips})
        res.summary = f"Resolved to: {', '.join(resolution.all_ips[:4])}"
        res.add_evidence(f"System resolver returned {len(resolution.all_ips)} address(es) for {hostname}")
        return check_from_result(f"DNS Resolution ({hostname})", res, details={"addresses": resolution.all_ips})

    # ------------------------------------------------------------------ #
    def http_request(self, url: str, label: str = "HTTP Request") -> CheckResult:
        self._report(f"Requesting {url} ...")
        timeout_ms = int(self.config.read_timeout * 1000)
        start = time.perf_counter()
        tid = f"http.basic.{url}"
        try:
            resp = requests.get(url, timeout=(self.config.connect_timeout + 1, self.config.read_timeout),
                                allow_redirects=True)
            elapsed = (time.perf_counter() - start) * 1000.0
            res = http_result_from_response(tid, url, resp.status_code, resp.url, elapsed, timeout_ms)
            res.metrics["redirected"] = resp.url.rstrip("/") != url.rstrip("/")
            details = {"status_code": resp.status_code, "final_url": resp.url, "elapsed_ms": round(elapsed, 1)}
        except requests.exceptions.RequestException as exc:
            elapsed = (time.perf_counter() - start) * 1000.0
            res = http_result_from_exception(tid, url, exc, elapsed, timeout_ms)
            details = {}
        return check_from_result(label, res, details=details)
