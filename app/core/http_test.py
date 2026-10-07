"""
http_test.py
============
HTTP testing as an ordered chain of *layers*, each with its own result:

    DNS -> TCP 443 -> TLS -> HTTP request/response -> redirect -> compression
                                                  -> HTTP/2 -> keep-alive
    DNS -> HTTP/3 (QUIC over UDP)            plain HTTP (port 80) + block-page check

When a layer fails, every layer that depends on it is reported as SKIPPED (blocked by
that layer) instead of producing a duplicate failure. Errors are classified: connection
failure, timeout, certificate problem, redirect, block page, unexpected status, and
content that does not look like the expected site.

HTTP/3 needs a QUIC stack. With the optional ``aioquic`` package a real QUIC handshake is
made; otherwise the ``Alt-Svc`` header is inspected and the result is labelled as a hint.
"""

from __future__ import annotations

import ipaddress
import re
import ssl
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable, Optional
from urllib.parse import urlparse

import httpx
import urllib3

from app.constants import (
    HTTP2_TEST_URL,
    HTTP3_TEST_HOST,
    HTTP_TEST_URL_PLAIN,
    HTTP_TEST_URL_TLS,
    REDIRECT_TEST_URL,
)
from app.core.basic_connectivity import http_result_from_exception, http_result_from_response
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

# The HTTPS test host is a Cloudflare site, which always answers with a ``cf-ray`` header.
# A 200 without it suggests that something other than the real site produced the response.
EXPECTED_SERVER_HEADER = "cf-ray"
PROXY_HEADERS = ("via", "proxy-authenticate", "x-squid-error", "x-bluecoat-via")


def _private(host: str | None) -> bool:
    try:
        return bool(host) and ipaddress.ip_address(host).is_private
    except ValueError:
        return False


def block_page_reasons(status_code: int, location: str, is_redirect: bool, body: str) -> list[str]:
    """Indicators of a block page in a plain-HTTP response (pure function, easy to test)."""
    reasons: list[str] = []
    if status_code == 451:
        reasons.append("HTTP 451 (unavailable for legal reasons)")
    host = urlparse(location).hostname
    if is_redirect and _private(host):
        reasons.append(f"redirect to a private address ({host})")
    if status_code < 400:
        for match in re.finditer(r"<iframe[^>]+src=[\"']?([^\"'>\s]+)", body[:4000].lower()):
            if _private(urlparse(match.group(1)).hostname):
                reasons.append("page embeds an iframe from a private address")
                break
    return reasons


class HTTPTester:
    def __init__(self, progress_cb: ProgressCallback = None, config: NetworkTestConfig = DEFAULT_CONFIG,
                 cancel: Optional[threading.Event] = None) -> None:
        self.progress_cb = progress_cb
        self.config = config
        self.cancel = cancel or threading.Event()
        self.host = urlparse(HTTP_TEST_URL_TLS).hostname or "www.cloudflare.com"

    def _report(self, message: str) -> None:
        if self.progress_cb:
            self.progress_cb(message)
        log.info(message)

    @property
    def _timeout(self) -> httpx.Timeout:
        return httpx.Timeout(self.config.read_timeout, connect=self.config.connect_timeout + 1)

    @property
    def _timeout_ms(self) -> int:
        return int(self.config.read_timeout * 1000)

    # ------------------------------------------------------------------ #
    # Layer chain
    # ------------------------------------------------------------------ #
    def _layers(self) -> tuple[list[CheckResult], list[TestResult], dict[str, bool]]:
        """DNS -> TCP -> TLS for the HTTPS test host. Returns checks, results and which layers passed."""
        checks: list[CheckResult] = []
        results: list[TestResult] = []
        ok = {"dns": False, "tcp": False, "tls": False}

        self._report(f"HTTP layer 1/3: DNS for {self.host} ...")
        resolution = resolve(self.host, "IPv4")
        if resolution.ok:
            dns = TestResult(f"http.layer.dns.{self.host}", "dns_resolution", target=self.host, protocol="DNS",
                             status=_S.SUCCESS, resolved_ip=resolution.ip, address_family=resolution.family,
                             duration_ms=resolution.duration_ms,
                             metadata={"role": "system", "domain": self.host, "layer": "dns",
                                       "addresses": resolution.all_ips},
                             summary=f"{self.host} resolved to {resolution.ip}.")
            ok["dns"] = True
        else:
            dns = dns_failure_result(f"http.layer.dns.{self.host}", self.host, resolution)
            dns.metadata["layer"] = "dns"
        results.append(dns)
        checks.append(check_from_result("HTTP Layer: DNS", dns))

        if ok["dns"]:
            self._report("HTTP layer 2/3: TCP 443 ...")
            tcp = tcp_probe(self.host, 443, self.config, resolution=resolution, role="reachability",
                            test_id=f"http.layer.tcp.{self.host}", cancel=self.cancel)
            tcp.metadata["layer"] = "tcp"
            ok["tcp"] = tcp.ok
        else:
            tcp = self._blocked(f"http.layer.tcp.{self.host}", "tcp", ["dns"], f"TCP 443 to {self.host}")
        results.append(tcp)
        checks.append(check_from_result("HTTP Layer: TCP 443", tcp))

        if ok["tcp"]:
            self._report("HTTP layer 3/3: TLS handshake ...")
            tls = self._tls_layer(resolution.ip)
            tls.metadata["layer"] = "tls"
            ok["tls"] = tls.ok
        else:
            blocker = "dns" if not ok["dns"] else "tcp"
            tls = self._blocked(f"http.layer.tls.{self.host}", "tls", [blocker], f"the TLS handshake with {self.host}")
        results.append(tls)
        checks.append(check_from_result("HTTP Layer: TLS", tls))
        return checks, results, ok

    def _tls_layer(self, ip: Optional[str]) -> TestResult:
        tls = TLSTester([self.host], config=self.config, cancel=self.cancel)
        return tls.handshake_phases(self.host, ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3,
                                    alpn=["h2", "http/1.1"], ip=ip, test_id=f"http.layer.tls.{self.host}")

    @staticmethod
    def _blocked(test_id: str, category: str, blockers: list[str], what: str) -> TestResult:
        res = TestResult(test_id, category, status=_S.SKIPPED, summary=f"Not tested: {what} depends on a layer that failed.")
        res.metadata.update(skip_reason="BLOCKED_BY_DEPENDENCY", blocked_by=[f"http.layer.{b}" for b in blockers],
                            role="handshake" if category == "tls" else "reachability")
        return res

    def _skipped_check(self, name: str, layer: str) -> CheckResult:
        res = self._blocked(f"http.{name}", "http", [layer], name)
        res.metadata["role"] = "layer_dependent"
        return check_from_result(name, res, message=f"Skipped - blocked by the failed {layer.upper()} layer.")

    # ------------------------------------------------------------------ #
    def run_all(self) -> ModuleReport:
        report = ModuleReport(module_name="HTTP Test")
        layer_checks, layer_results, ok = self._layers()
        for c in layer_checks:
            report.add(c)
        report.results += layer_results

        # step name -> (callable, the layer it needs)
        steps: list[tuple[str, Callable[[], CheckResult], str]] = [
            ("Plain HTTP", self._plain_http, "dns"),
            ("Block Page Detection", self._block_page_check, "dns"),
            ("HTTPS", self._https, "tls"),
            ("HTTP/2 Support", self._http2, "tls"),
            ("HTTP/3 (QUIC) Support", self._http3_hint, "dns"),
            ("HTTP Redirect", self._redirect, "dns"),
            ("Response Compression", self._compression, "tls"),
            ("Connection Reuse (Keep-Alive)", self._connection_reuse, "tls"),
        ]
        runnable = [(n, f) for n, f, need in steps if ok[need] and not self.cancel.is_set()]
        with ThreadPoolExecutor(max_workers=max(1, min(len(runnable) or 1, self.config.max_concurrency)),
                                thread_name_prefix="icpa-http") as pool:
            futures = {n: pool.submit(self._safe, n, f) for n, f in runnable}
            for name, _f, need in steps:
                if name in futures:
                    report.add(futures[name].result())
                elif not ok[need]:
                    report.add(self._skipped_check(name, need))
        report.finish()
        return report

    def _safe(self, name: str, func: Callable[[], CheckResult]) -> CheckResult:
        try:
            return func()
        except Exception as exc:  # noqa: BLE001 - one step must not break the module
            log.exception("HTTP step %s crashed", name)
            res = TestResult(f"http.{name}", "http", status=_S.ERROR, error_type=type(exc).__name__,
                             error_message=str(exc)[:200], metadata={"role": "error"},
                             summary=f"{name} could not be completed (internal error).")
            return check_from_result(name, res, message=f"{name} could not be completed ({type(exc).__name__}).")

    # ------------------------------------------------------------------ #
    def _get(self, test_id: str, role: str, url: str, **kw: Any) -> tuple[Optional[httpx.Response], TestResult]:
        """One request, normalized: returns (response or None, TestResult)."""
        start = time.perf_counter()
        try:
            resp = httpx.get(url, timeout=self._timeout, **kw)
        except httpx.HTTPError as exc:
            res = http_result_from_exception(test_id, url, exc, (time.perf_counter() - start) * 1000.0, self._timeout_ms)
            res.metadata["role"] = role
            return None, res
        res = http_result_from_response(test_id, url, resp.status_code, str(resp.url),
                                        (time.perf_counter() - start) * 1000.0, self._timeout_ms)
        res.metadata["role"] = role
        res.metrics["http_version"] = resp.http_version
        proxy = {h: resp.headers[h] for h in PROXY_HEADERS if h in resp.headers}
        if proxy:
            res.metadata["proxy_headers"] = proxy
            res.add_evidence("The response carries proxy headers: " + ", ".join(proxy))
            if res.status in (_S.HTTP_FAILED, _S.BLOCKED):
                res.interpretation, res.confidence = "PROXY_GENERATED_RESPONSE_POSSIBLE", 0.5
        return resp, res

    def _plain_http(self) -> CheckResult:
        self._report("Testing plain HTTP ...")
        resp, res = self._get("http.plain", "plain", HTTP_TEST_URL_PLAIN, follow_redirects=True)
        details = {"status_code": resp.status_code, "url": str(resp.url)} if resp else {}
        return check_from_result("Plain HTTP", res, details=details)

    def _block_page_check(self) -> CheckResult:
        """
        Plain HTTP can be rewritten by anything on the path, so a block page shows up here first:
        an explicit 451, or a redirect/iframe pointing at a private (LAN-style) address.
        """
        self._report("Checking plain HTTP for block pages ...")
        start = time.perf_counter()
        res = TestResult("http.block_page", "http", target=HTTP_TEST_URL_PLAIN, protocol="HTTP",
                         metadata={"role": "block_page"})
        try:
            response = httpx.get(HTTP_TEST_URL_PLAIN, timeout=self._timeout, follow_redirects=False)
        except httpx.HTTPError as exc:
            err = normalize_wrapped_exception(exc)
            res.status, res.severity, res.error_code = _S.INCONCLUSIVE, Severity.INFO, err.error_code
            res.summary = f"Could not run the check: {exc.__class__.__name__}."
            return check_from_result("Block Page Detection", res, message=res.summary)
        res.duration_ms = (time.perf_counter() - start) * 1000.0
        reasons = block_page_reasons(response.status_code, response.headers.get("location", ""),
                                     response.is_redirect, response.text if response.status_code < 400 else "")
        if reasons:
            res.status, res.interpretation, res.confidence = _S.BLOCKED, "POSSIBLE_BLOCK_PAGE", 0.75
            res.summary = "Signs of a block page: " + "; ".join(reasons) + "."
            for r in reasons:
                res.add_evidence(r)
            return check_from_result("Block Page Detection", res, details={"reasons": reasons, "suspected": True})
        res.status = _S.SUCCESS
        res.summary = "No block page indicators in the plain HTTP response."
        return check_from_result("Block Page Detection", res, details={"suspected": False})

    def _https(self) -> CheckResult:
        self._report("Testing HTTPS ...")
        resp, res = self._get("http.https", "https", HTTP_TEST_URL_TLS, follow_redirects=True)
        details: dict[str, Any] = {}
        if resp is not None:
            details = {"status_code": resp.status_code, "url": str(resp.url)}
            if res.ok and EXPECTED_SERVER_HEADER not in resp.headers:
                res.status, res.severity = _S.PARTIAL, Severity.WARNING
                res.interpretation, res.confidence = "CONTENT_MISMATCH_POSSIBLE", 0.4
                res.warnings.append("The response lacks the headers the real site always sends; "
                                    "an intermediate device may have produced it.")
        return check_from_result("HTTPS", res, details=details)

    def _http2(self) -> CheckResult:
        self._report("Testing HTTP/2 ...")
        start = time.perf_counter()
        res = TestResult("http.http2", "http", target=HTTP2_TEST_URL, protocol="HTTP/2", metadata={"role": "http2"})
        try:
            with httpx.Client(http2=True, timeout=self._timeout) as client:
                resp = client.get(HTTP2_TEST_URL)
        except ImportError:
            res.status, res.severity = _S.INCONCLUSIVE, Severity.INFO
            res.summary = "The optional 'h2' package is not installed - HTTP/2 could not be tested."
            return check_from_result("HTTP/2 Support", res, message=res.summary)
        except httpx.HTTPError as exc:
            failed = http_result_from_exception("http.http2", HTTP2_TEST_URL, exc,
                                                (time.perf_counter() - start) * 1000.0, self._timeout_ms)
            failed.protocol, failed.metadata["role"] = "HTTP/2", "http2"
            return check_from_result("HTTP/2 Support", failed)
        res.duration_ms = (time.perf_counter() - start) * 1000.0
        res.metrics["http_version"] = resp.http_version
        if resp.http_version == "HTTP/2":
            res.status = _S.SUCCESS
            res.summary = f"Server negotiated HTTP/2 in {res.duration_ms:.0f} ms."
        else:
            res.status, res.severity = _S.PARTIAL, Severity.WARNING
            res.summary = f"Connected, but negotiated {resp.http_version} instead of HTTP/2."
        return check_from_result("HTTP/2 Support", res, details={"http_version": resp.http_version})

    def _http3_hint(self) -> CheckResult:
        self._report("Checking HTTP/3 (QUIC) support ...")
        try:
            return self._http3_real_handshake()
        except ImportError:
            return self._http3_altsvc_hint()

    def _http3_real_handshake(self) -> CheckResult:
        import asyncio

        from aioquic.asyncio.client import connect
        from aioquic.h3.connection import H3_ALPN
        from aioquic.quic.configuration import QuicConfiguration

        res = TestResult("http.http3", "http", target=HTTP3_TEST_HOST, protocol="HTTP/3 (QUIC)", port=443,
                         metadata={"role": "http3"}, timeout_ms=6000)

        async def _try_connect() -> float:
            config = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN)
            config.verify_mode = 0  # do not fail on cert issues for this probe
            start = time.perf_counter()
            async with connect(HTTP3_TEST_HOST, 443, configuration=config) as client:
                await client.wait_connected()
            return (time.perf_counter() - start) * 1000.0

        try:
            duration_ms = asyncio.run(asyncio.wait_for(_try_connect(), timeout=6))
        except Exception as exc:  # noqa: BLE001 - classified, not hidden
            err = normalize_wrapped_exception(exc)
            res.status = _S.TIMEOUT if err.error_code == "TIMEOUT" or isinstance(exc, asyncio.TimeoutError) else _S.HTTP_FAILED
            res.severity = Severity.WARNING        # HTTP/3 is optional: its failure never means "no Internet"
            res.error_type, res.error_code, res.error_message = type(exc).__name__, err.error_code, str(exc)[:200]
            res.interpretation = "QUIC_UDP_BLOCKED_OR_UNSUPPORTED"
            res.confidence = 0.4
            res.summary = f"QUIC handshake failed: {exc or type(exc).__name__}"
            return check_from_result("HTTP/3 (QUIC) Support", res)
        res.status, res.duration_ms = _S.SUCCESS, duration_ms
        res.summary = f"QUIC handshake with {HTTP3_TEST_HOST} succeeded in {duration_ms:.0f} ms."
        return check_from_result("HTTP/3 (QUIC) Support", res)

    def _http3_altsvc_hint(self) -> CheckResult:
        res = TestResult("http.http3", "http", target=HTTP_TEST_URL_TLS, protocol="HTTP/3 (hint)",
                         metadata={"role": "http3", "hint_only": True})
        try:
            resp = httpx.get(HTTP_TEST_URL_TLS, timeout=self._timeout)
        except httpx.HTTPError as exc:
            res.status, res.severity = _S.INCONCLUSIVE, Severity.INFO
            res.summary = f"Could not check Alt-Svc hint: {exc}"
            return check_from_result("HTTP/3 (QUIC) Support", res, message=res.summary)
        alt_svc = resp.headers.get("alt-svc", "")
        if "h3" in alt_svc:
            res.status = _S.SUCCESS
            res.summary = ("Server advertises HTTP/3 via Alt-Svc header (indirect hint, QUIC handshake not "
                           "performed - install 'aioquic' for a real test).")
        else:
            res.status, res.severity = _S.INCONCLUSIVE, Severity.INFO
            res.summary = "Server did not advertise HTTP/3 via Alt-Svc (install 'aioquic' for a real QUIC handshake test)."
        return check_from_result("HTTP/3 (QUIC) Support", res, details={"alt_svc": alt_svc})

    def _redirect(self) -> CheckResult:
        self._report("Testing HTTP redirect handling ...")
        resp, res = self._get("http.redirect", "redirect", REDIRECT_TEST_URL, follow_redirects=True)
        if resp is None:
            return check_from_result("HTTP Redirect", res)
        redirects = len(resp.history)
        res.metrics["redirect_count"] = redirects
        res.summary = (f"Followed {redirects} redirect(s) to {resp.url}." if redirects
                       else "No redirect occurred; final response received directly.")
        if res.status is _S.HTTP_FAILED:      # the redirect chain ended in an error status
            res.summary += f" Final status: HTTP {resp.status_code}."
        return check_from_result("HTTP Redirect", res, details={"redirect_count": redirects, "final_url": str(resp.url)})

    def _compression(self) -> CheckResult:
        self._report("Testing response compression ...")
        resp, res = self._get("http.compression", "compression", HTTP_TEST_URL_TLS,
                              headers={"Accept-Encoding": "gzip, br, deflate"})
        if resp is None:
            return check_from_result("Response Compression", res)
        encoding = resp.headers.get("content-encoding")
        if encoding:
            res.status, res.severity = _S.SUCCESS, Severity.OK
            res.summary = f"Server compressed the response using '{encoding}'."
        else:
            res.status, res.severity = _S.PARTIAL, Severity.WARNING
            res.summary = "Server did not compress the response body."
        return check_from_result("Response Compression", res, details={"content_encoding": encoding})

    def _connection_reuse(self) -> CheckResult:
        self._report("Testing TCP connection reuse (keep-alive) ...")
        # urllib3's pool counts the TCP connections it really opened, so two requests over exactly
        # one connection is proof of reuse (not a guess).
        res = TestResult("http.keepalive", "http", target=self.host, protocol="HTTPS", port=443,
                         metadata={"role": "keepalive"})
        pool = urllib3.HTTPSConnectionPool(self.host, port=443, maxsize=1, timeout=self.config.read_timeout)
        try:
            start = time.perf_counter()
            pool.request("GET", "/", retries=False)
            first_ms = (time.perf_counter() - start) * 1000.0
            start = time.perf_counter()
            pool.request("GET", "/", retries=False)
            second_ms = (time.perf_counter() - start) * 1000.0
            connections, made = pool.num_connections, pool.num_requests
            details = {"connections_opened": connections, "requests_made": made,
                       "first_request_ms": round(first_ms, 1), "second_request_ms": round(second_ms, 1)}
            res.metrics.update(details)
            if connections == 1 and made == 2:
                res.status = _S.SUCCESS
                res.summary = (f"Two requests shared one TCP connection (first {first_ms:.0f} ms, "
                               f"second {second_ms:.0f} ms).")
            else:
                res.status, res.severity = _S.PARTIAL, Severity.WARNING
                res.summary = (f"The server or network closed the connection between requests "
                               f"({connections} connections opened for {made} requests).")
            return check_from_result("Connection Reuse (Keep-Alive)", res, details=details)
        except urllib3.exceptions.HTTPError as exc:
            err = normalize_wrapped_exception(exc)
            res.status, res.error_code, res.error_message = _S.HTTP_FAILED, err.error_code, err.error_message
            res.severity = Severity.WARNING
            res.summary = f"Failed: {err.error_message}"
            return check_from_result("Connection Reuse (Keep-Alive)", res)
        finally:
            pool.close()
