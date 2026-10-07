"""
site_reachability.py
====================
Checks websites layer by layer - DNS, then TCP (port 443), then TLS
(with the site's name as SNI), then HTTPS - and reports the FIRST layer
that fails. Knowing where a connection breaks is far more informative
than a plain "cannot open":

    DNS fails / returns a private address  -> name-level interference
    TCP times out or is reset              -> address-level blocking or outage
    TCP works but TLS is cut               -> consistent with SNI/ClientHello inspection
    TLS works but HTTP says 451 / redirects
    to a private address                   -> block page

A few CONTROL sites are tested as well. If the controls work while some
test sites fail, the problem is specific to those sites; if the controls
fail too, the whole connection is unhealthy and per-site results say little.

The layered approach follows the methodology of community tools such as
MayersScott/rkn-block-checker and OONI; this implementation is original.
"""

from __future__ import annotations

import errno
import ipaddress
import re
import socket
import ssl
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, Optional
from urllib.parse import urlparse

import httpx

from app.constants import (
    SITE_CHECK_TIMEOUT,
    SITE_CONTROL_HOSTS,
    SITE_DEFAULT_TEST_HOSTS,
    SITE_HTTP_BLOCK_STATUS,
    SITE_MAX_CUSTOM_HOSTS,
)
from app.core.dns_test import is_suspicious_answer
from app.core.tcp_scanner import classify_connect_result
from app.logger import get_logger
from app.models import CheckResult, ModuleReport, Status
from app.utils.helpers import resolve_host

log = get_logger(__name__)

ProgressCallback = Optional[Callable[[str], None]]

_HOST_RE = re.compile(
    r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)


def sanitize_hosts(raw_hosts: list[str], limit: int = SITE_MAX_CUSTOM_HOSTS) -> list[str]:
    """
    Turn user input into a clean list of unique domain names.
    Accepts "https://Example.com/path", "example.com:443" etc.; anything that
    is not a plain domain name (IP literals included) is dropped.
    """
    cleaned: list[str] = []
    for item in raw_hosts:
        text = item.strip().lower()
        if not text:
            continue
        if "://" in text:
            text = urlparse(text).hostname or ""
        text = text.split("/")[0].split(":")[0].strip(".")
        if _HOST_RE.match(text) and text not in cleaned:
            cleaned.append(text)
        if len(cleaned) >= limit:
            break
    return cleaned


class SiteReachabilityTester:
    def __init__(self, test_hosts: Optional[list[str]] = None,
                 progress_cb: ProgressCallback = None) -> None:
        self.test_hosts = sanitize_hosts(test_hosts) if test_hosts else list(SITE_DEFAULT_TEST_HOSTS)
        self.control_hosts = list(SITE_CONTROL_HOSTS)
        self.progress_cb = progress_cb

    def _report(self, message: str) -> None:
        if self.progress_cb:
            self.progress_cb(message)
        log.info(message)

    # ------------------------------------------------------------------ #
    def run_all(self) -> ModuleReport:
        report = ModuleReport(module_name="Website Reachability")
        jobs = [(h, True) for h in self.control_hosts] + \
               [(h, False) for h in self.test_hosts if h not in self.control_hosts]

        self._report(f"Checking {len(jobs)} website(s) layer by layer ...")
        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(lambda job: self.check_site(job[0], job[1]), jobs))

        for result in results:
            report.add(result)
        report.add(self._summarize(results))
        report.finish()
        return report

    # ------------------------------------------------------------------ #
    def check_site(self, host: str, is_control: bool) -> CheckResult:
        label = "control" if is_control else "test"
        name = f"Site {host} ({label})"
        timings: dict[str, float] = {}
        details: dict = {"host": host, "control": is_control, "timings_ms": timings,
                         "failed_stage": None}

        def fail(stage: str, status: Status, message: str) -> CheckResult:
            details["failed_stage"] = stage
            return CheckResult(name=name, status=status, message=message, details=details,
                               duration_ms=sum(timings.values()) or None)

        # ---- 1. DNS ----------------------------------------------------
        start = time.perf_counter()
        addresses = resolve_host(host, family=socket.AF_INET, timeout=SITE_CHECK_TIMEOUT)
        timings["dns"] = (time.perf_counter() - start) * 1000.0
        details["addresses"] = addresses
        if not addresses:
            return fail("dns", Status.FAILED,
                        "DNS lookup failed - the name could not be resolved.")
        if all(is_suspicious_answer(ip) for ip in addresses):
            return fail("dns", Status.FAILED,
                        f"DNS returned only a private/loopback address ({addresses[0]}). "
                        "That is typical of a block page or DNS tampering.")
        ip = next((a for a in addresses if not is_suspicious_answer(a)), addresses[0])

        # ---- 2. TCP ----------------------------------------------------
        start = time.perf_counter()
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(SITE_CHECK_TIMEOUT)
                code = sock.connect_ex((ip, 443))
        except socket.timeout:
            code = errno.ETIMEDOUT
        except OSError as exc:
            code = exc.errno if exc.errno is not None else -1
        timings["tcp"] = (time.perf_counter() - start) * 1000.0
        state = classify_connect_result(code)
        details["tcp_state"] = state
        if state != "open":
            explain = {
                "timeout": "no answer (packets may be dropped)",
                "reset": "the connection was reset",
                "closed": "the connection was refused",
                "filtered": "the network reported the address as unreachable",
            }[state]
            return fail("tcp", Status.FAILED, f"TCP port 443 on {ip}: {explain}.")

        # ---- 3. TLS (with SNI = host, full certificate validation) -------
        start = time.perf_counter()
        context = ssl.create_default_context()
        try:
            with socket.create_connection((ip, 443), timeout=SITE_CHECK_TIMEOUT) as raw:
                with context.wrap_socket(raw, server_hostname=host) as tls:
                    details["tls_version"] = tls.version()
        except ssl.SSLCertVerificationError as exc:
            timings["tls"] = (time.perf_counter() - start) * 1000.0
            return fail("tls", Status.FAILED,
                        f"The server's certificate did not validate ({exc.verify_message}). "
                        "This can mean TLS interception, but also an antivirus/proxy or captive portal.")
        except ConnectionResetError:
            timings["tls"] = (time.perf_counter() - start) * 1000.0
            return fail("tls", Status.FAILED,
                        "TCP connected, but the TLS handshake was reset. Consistent with a "
                        "device inspecting the SNI name, though not proof.")
        except ssl.SSLEOFError:
            timings["tls"] = (time.perf_counter() - start) * 1000.0
            return fail("tls", Status.FAILED,
                        "TCP connected, but the connection was closed during the TLS handshake. "
                        "Consistent with SNI/ClientHello inspection, though not proof.")
        except (socket.timeout, TimeoutError):
            timings["tls"] = (time.perf_counter() - start) * 1000.0
            return fail("tls", Status.FAILED,
                        "TCP connected, but the TLS handshake timed out (packets after the "
                        "ClientHello may be dropped).")
        except (ssl.SSLError, OSError) as exc:
            timings["tls"] = (time.perf_counter() - start) * 1000.0
            return fail("tls", Status.FAILED, f"TLS handshake failed: {exc}")
        timings["tls"] = (time.perf_counter() - start) * 1000.0

        # ---- 4. HTTPS ----------------------------------------------------
        start = time.perf_counter()
        try:
            response = httpx.get(f"https://{host}/", timeout=SITE_CHECK_TIMEOUT,
                                 follow_redirects=False,
                                 headers={"User-Agent": "Mozilla/5.0 ICPA-diagnostic"})
        except httpx.HTTPError as exc:
            timings["http"] = (time.perf_counter() - start) * 1000.0
            return fail("http", Status.WARNING,
                        f"TLS worked but the HTTPS request failed ({exc.__class__.__name__}).")
        timings["http"] = (time.perf_counter() - start) * 1000.0
        details["http_status"] = response.status_code

        if response.status_code == SITE_HTTP_BLOCK_STATUS:
            return fail("http", Status.FAILED,
                        "The server answered HTTP 451 (unavailable for legal reasons), "
                        "which is an explicit block page status.")
        location = response.headers.get("location", "")
        if response.is_redirect and location:
            target_host = urlparse(location).hostname or ""
            try:
                if ipaddress.ip_address(target_host).is_private:
                    return fail("http", Status.FAILED,
                                f"The site redirected to a private address ({target_host}), "
                                "which is typical of a block page.")
            except ValueError:
                pass  # a normal domain name, not an IP literal

        total = sum(timings.values())
        return CheckResult(
            name=name, status=Status.OK,
            message=(f"Reachable on every layer (HTTP {response.status_code}, "
                     f"DNS {timings['dns']:.0f} ms, TCP {timings['tcp']:.0f} ms, "
                     f"TLS {timings['tls']:.0f} ms)."),
            details=details, duration_ms=total,
        )

    # ------------------------------------------------------------------ #
    def _summarize(self, results: list[CheckResult]) -> CheckResult:
        controls = [r for r in results if r.details.get("control")]
        tests = [r for r in results if not r.details.get("control")]
        control_failed = [r for r in controls if r.status != Status.OK]
        test_failed = [r for r in tests if r.status != Status.OK]

        stages: dict[str, int] = {}
        for r in test_failed:
            stage = r.details.get("failed_stage") or "unknown"
            stages[stage] = stages.get(stage, 0) + 1

        details = {
            "control_total": len(controls), "control_failed": len(control_failed),
            "test_total": len(tests), "test_failed": len(test_failed),
            "failed_stages": stages,
        }

        if controls and len(control_failed) == len(controls):
            return CheckResult(
                name="Control vs Test Comparison", status=Status.FAILED,
                message=("Even the control sites failed, so the connection itself looks unhealthy. "
                         "Results for the other sites say little about site-specific blocking."),
                details=details)
        if test_failed:
            where = ", ".join(f"{n} at {s}" for s, n in sorted(stages.items()))
            return CheckResult(
                name="Control vs Test Comparison", status=Status.WARNING,
                message=(f"{len(test_failed)} of {len(tests)} test site(s) failed ({where}) while the "
                         "control sites worked. That points to something specific to those sites "
                         "rather than a general outage - a possibility, not a certainty."),
                details=details)
        return CheckResult(
            name="Control vs Test Comparison", status=Status.OK,
            message=f"All {len(tests)} test site(s) were reachable on every layer.",
            details=details)
