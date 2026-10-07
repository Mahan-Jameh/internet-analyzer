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

import ipaddress
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable, Optional
from urllib.parse import urlparse

import httpx

from app.constants import (
    SITE_CONTROL_HOSTS,
    SITE_DEFAULT_TEST_HOSTS,
    SITE_HTTP_BLOCK_STATUS,
    SITE_MAX_CUSTOM_HOSTS,
)
from app.core.dns_test import is_suspicious_answer
from app.core.tls_test import TLSTester
from app.diag.adapter import check_from_result
from app.diag.neterrors import normalize_wrapped_exception
from app.diag.probes import dns_failure_result, resolve, tcp_probe
from app.diag.results import Severity, TechnicalStatus, TestResult
from app.diag.testconfig import DEFAULT_CONFIG, NetworkTestConfig
from app.logger import get_logger
from app.models import CheckResult, ModuleReport, Status

log = get_logger(__name__)
_S = TechnicalStatus

ProgressCallback = Optional[Callable[[str], None]]

_HOST_RE = re.compile(
    r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)
LAYERS = ("dns", "tcp", "tls", "http")


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
                 progress_cb: ProgressCallback = None,
                 config: NetworkTestConfig = DEFAULT_CONFIG,
                 cancel: Optional[threading.Event] = None) -> None:
        self.test_hosts = sanitize_hosts(test_hosts) if test_hosts else list(SITE_DEFAULT_TEST_HOSTS)
        self.control_hosts = list(SITE_CONTROL_HOSTS)
        self.progress_cb = progress_cb
        self.config = config
        self.cancel = cancel or threading.Event()
        self._tls = TLSTester(config=config, cancel=self.cancel)

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
        workers = max(1, min(len(jobs), self.config.max_concurrency, 4))
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="icpa-site") as pool:
            results = list(pool.map(lambda job: self._safe_check(*job), jobs))

        for result in results:
            report.add(result)
            chain = result.details.get("layer_results") or []
            report.results.extend(r for r in chain if isinstance(r, TestResult))
        report.add(self._summarize(results))
        report.finish()
        return report

    def _safe_check(self, host: str, is_control: bool) -> CheckResult:
        try:
            return self.check_site(host, is_control)
        except Exception as exc:  # noqa: BLE001 - one site must never break the module
            log.exception("Site check crashed for %s", host)
            label = "control" if is_control else "test"
            res = TestResult(f"site.{host}", "site", status=_S.ERROR, target=host,
                             error_type=type(exc).__name__, error_message=str(exc)[:200],
                             metadata={"role": label, "failed_layer": "internal"},
                             summary=f"{host}: internal error while testing.")
            return check_from_result(f"Site {host} ({label})", res,
                                     details={"host": host, "control": is_control, "failed_stage": "internal"})

    # ------------------------------------------------------------------ #
    def check_site(self, host: str, is_control: bool) -> CheckResult:
        label = "control" if is_control else "test"
        name = f"Site {host} ({label})"
        cfg = self.config
        timings: dict[str, float] = {}
        chain: list[TestResult] = []
        layer_status: dict[str, str] = {layer: "SKIPPED" for layer in LAYERS}
        details: dict[str, Any] = {"host": host, "control": is_control, "timings_ms": timings,
                                   "failed_stage": None, "layers": layer_status}

        site = TestResult(f"site.{host}", "site", target=host, protocol="HTTPS", port=443,
                          metadata={"role": label, "failed_layer": None},
                          metrics={"layers": layer_status})

        def finish(failed_layer: Optional[str], status: _S, summary: str, severity: Severity,
                   interpretation: Optional[str] = None, confidence: Optional[float] = None,
                   cause: Optional[TestResult] = None) -> CheckResult:
            site.status, site.summary, site.severity = status, summary, severity
            site.interpretation, site.confidence = interpretation, confidence
            site.metadata["failed_layer"] = failed_layer
            site.duration_ms = sum(timings.values()) or None
            if cause is not None:
                site.error_code, site.error_type = cause.error_code, cause.error_type
                site.error_message, site.platform_error = cause.error_message, cause.platform_error
            details["failed_stage"] = failed_layer
            details["layer_results"] = chain
            if failed_layer:
                for layer in LAYERS[LAYERS.index(failed_layer) + 1:]:
                    layer_status[layer] = "SKIPPED"
            chain.append(site)
            check = check_from_result(name, site, details=details)
            return check

        # ---- 1. DNS (system resolver) -------------------------------------
        res = resolve(host)
        timings["dns"] = res.duration_ms
        v6 = resolve(host, "IPv6") if res.ok else None
        details["addresses"] = res.all_ips
        details["ipv6_available_in_dns"] = bool(v6 and v6.ok)
        if not res.ok:
            r = dns_failure_result(f"site.{host}.dns", host, res, role=label,
                                   timeout_ms=int(cfg.dns_timeout * 1000))
            layer_status["dns"] = r.status.value
            chain.append(r)
            return finish("dns", _S.DNS_FAILED, f"{host}: DNS lookup failed ({r.error_code}).",
                          Severity.ERROR, "NAME_NOT_RESOLVED", 0.7, cause=r)
        public = [a for a in res.all_ips if not is_suspicious_answer(a)]
        dns_ok = TestResult(f"site.{host}.dns", "dns_resolution", status=_S.SUCCESS, target=host,
                            protocol="DNS", duration_ms=res.duration_ms, metadata={"role": label},
                            summary=f"{host} resolved to {', '.join(res.all_ips[:3])}.")
        chain.append(dns_ok)
        layer_status["dns"] = "SUCCESS"
        if not public:
            dns_ok.status = _S.DNS_FAILED
            dns_ok.error_code = "PRIVATE_ADDRESS_ANSWER"
            dns_ok.interpretation, dns_ok.confidence = "POSSIBLE_DNS_TAMPERING", 0.6
            dns_ok.add_evidence(f"Only private/loopback addresses were returned ({res.all_ips[0]}).")
            layer_status["dns"] = "DNS_FAILED"
            return finish("dns", _S.DNS_FAILED,
                          f"DNS returned only a private/loopback address ({res.all_ips[0]}). "
                          "That is typical of a block page or DNS tampering, but a corporate or "
                          "local network can do this legitimately too.",
                          Severity.ERROR, "POSSIBLE_DNS_TAMPERING", 0.6, cause=dns_ok)
        ip = public[0]
        site.resolved_ip = ip
        site.address_family = "IPv6" if ":" in ip else "IPv4"

        # ---- 2. TCP --------------------------------------------------------
        if self.cancel.is_set():
            return finish("tcp", _S.SKIPPED, "Cancelled.", Severity.SKIPPED)
        tcp = tcp_probe(host, 443, cfg, resolution=_pinned(res, ip), role=label,
                        test_id=f"site.{host}.tcp", cancel=self.cancel)
        timings["tcp"] = tcp.duration_ms or 0.0
        chain.append(tcp)
        layer_status["tcp"] = tcp.status.value
        details["tcp_state"] = tcp.status.value
        if not tcp.ok:
            return finish("tcp", tcp.status, f"TCP port 443 on {ip}: {tcp.summary}",
                          Severity.ERROR, tcp.interpretation, tcp.confidence, cause=tcp)

        # ---- 3. TLS (SNI = host, full certificate validation) -----------------
        import ssl as _ssl
        tls = self._tls.handshake_phases(host, _ssl.TLSVersion.TLSv1_2, _ssl.TLSVersion.TLSv1_3,
                                         ip=ip, test_id=f"site.{host}.tls", role=label)
        timings["tls"] = tls.metrics.get("handshake_ms", tls.duration_ms or 0.0)
        chain.append(tls)
        layer_status["tls"] = tls.status.value
        if tls.ok:
            details["tls_version"] = tls.metrics.get("tls_version")
        else:
            tls.severity = Severity.ERROR
            hint = {
                "CERTIFICATE_ERROR": " This can mean TLS interception, but also an antivirus, proxy or captive portal.",
                "CERTIFICATE_HOSTNAME_MISMATCH": " The certificate belongs to a different name than requested.",
            }.get(tls.error_code or "", " Consistent with SNI/ClientHello inspection, though not proof."
                  if tls.status in (_S.TLS_FAILED, _S.RESET, _S.TIMEOUT) else "")
            return finish("tls", tls.status,
                          f"TCP connected, but the TLS handshake failed ({tls.error_code}).{hint}",
                          Severity.ERROR, tls.interpretation, 0.5, cause=tls)

        # ---- 4. HTTPS --------------------------------------------------------
        start = time.perf_counter()
        http = TestResult(f"site.{host}.http", "http", target=host, resolved_ip=ip, protocol="HTTPS",
                          port=443, metadata={"role": label},
                          timeout_ms=int(cfg.read_timeout * 1000))
        chain.append(http)
        try:
            response = httpx.get(f"https://{host}/", timeout=httpx.Timeout(cfg.read_timeout, connect=cfg.connect_timeout),
                                 follow_redirects=False,
                                 headers={"User-Agent": "Mozilla/5.0 ICPA-diagnostic"})
        except httpx.HTTPError as exc:
            timings["http"] = (time.perf_counter() - start) * 1000.0
            norm = normalize_wrapped_exception(exc)
            http.duration_ms = timings["http"]
            http.status, http.error_code, http.error_type = _S.HTTP_FAILED, norm.error_code, norm.error_type
            http.error_message, http.severity = norm.error_message, Severity.WARNING
            layer_status["http"] = http.status.value
            return finish("http", _S.HTTP_FAILED,
                          f"TLS worked but the HTTPS request failed ({norm.error_code}).",
                          Severity.WARNING, "HTTP_REQUEST_FAILED", 0.5, cause=http)
        timings["http"] = (time.perf_counter() - start) * 1000.0
        http.duration_ms = timings["http"]
        http.metrics.update(status_code=response.status_code, http_version=response.http_version)
        details["http_status"] = response.status_code

        reason = None
        if response.status_code == SITE_HTTP_BLOCK_STATUS:
            reason = ("The server answered HTTP 451 (unavailable for legal reasons), "
                      "which is an explicit block page status.")
        else:
            location = response.headers.get("location", "")
            if response.is_redirect and location:
                target_host = urlparse(location).hostname or ""
                try:
                    if ipaddress.ip_address(target_host).is_private:
                        reason = (f"The site redirected to a private address ({target_host}), "
                                  "which is typical of a block page.")
                except ValueError:
                    pass  # a normal domain name, not an IP literal
        if reason:
            http.status, http.severity = _S.BLOCKED, Severity.ERROR
            http.interpretation, http.confidence = "BLOCK_PAGE_INDICATOR", 0.7
            layer_status["http"] = "BLOCKED"
            return finish("http", _S.BLOCKED, reason, Severity.ERROR, "BLOCK_PAGE_INDICATOR", 0.7, cause=http)

        http.status = _S.SUCCESS
        http.summary = f"HTTPS answered with status {response.status_code}."
        layer_status["http"] = "SUCCESS"
        site.metrics.update(timings_ms={k: round(v, 1) for k, v in timings.items()})
        return finish(
            None, _S.SUCCESS,
            (f"Reachable on every layer (HTTP {response.status_code}, DNS {timings['dns']:.0f} ms, "
             f"TCP {timings['tcp']:.0f} ms, TLS {timings['tls']:.0f} ms)."),
            Severity.OK)

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


def _pinned(res, ip):  # noqa: ANN001
    """A Resolution that pins the already-resolved, non-suspicious address."""
    from dataclasses import replace
    return replace(res, ip=ip, family="IPv6" if ":" in ip else "IPv4")
