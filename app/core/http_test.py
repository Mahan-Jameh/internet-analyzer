"""
http_test.py
============
Tests the HTTP layer specifically: protocol negotiation (HTTP/1.1,
HTTP/2, and an HTTP/3 support hint), redirects, response compression
and TCP connection reuse (keep-alive).

HTTP/3 (QUIC) requires a full QUIC client stack. Where the optional
``aioquic`` package is available we perform a real QUIC handshake;
otherwise we fall back to inspecting the ``Alt-Svc`` header of a normal
HTTPS response (a widely used, though indirect, signal that a server
advertises HTTP/3 support) and clearly label the result as a hint.
"""

from __future__ import annotations

import ipaddress
import re
import time
from typing import Callable, Optional
from urllib.parse import urlparse

import httpx
import urllib3

from app.constants import (
    HTTP2_TEST_URL,
    HTTP3_TEST_HOST,
    HTTP_TEST_URL_PLAIN,
    HTTP_TEST_URL_TLS,
    HTTP_TIMEOUT,
    REDIRECT_TEST_URL,
)
from app.logger import get_logger
from app.models import CheckResult, ModuleReport, Status

log = get_logger(__name__)

ProgressCallback = Optional[Callable[[str], None]]


class HTTPTester:
    def __init__(self, progress_cb: ProgressCallback = None) -> None:
        self.progress_cb = progress_cb

    def _report(self, message: str) -> None:
        if self.progress_cb:
            self.progress_cb(message)
        log.info(message)

    def run_all(self) -> ModuleReport:
        report = ModuleReport(module_name="HTTP Test")

        report.add(self._plain_http())
        report.add(self._block_page_check())
        report.add(self._https())
        report.add(self._http2())
        report.add(self._http3_hint())
        report.add(self._redirect())
        report.add(self._compression())
        report.add(self._connection_reuse())

        report.finish()
        return report

    # ------------------------------------------------------------------ #
    def _block_page_check(self) -> CheckResult:
        """
        Plain HTTP can be rewritten by anything on the path, so a block page
        shows up here first: an explicit 451 status, or a redirect/iframe
        pointing at a private (LAN-style) address that a real site never uses.
        """
        self._report("Checking plain HTTP for block pages ...")
        name = "Block Page Detection"
        try:
            response = httpx.get(HTTP_TEST_URL_PLAIN, timeout=HTTP_TIMEOUT, follow_redirects=False)
        except httpx.HTTPError as exc:
            return CheckResult(name=name, status=Status.UNKNOWN,
                               message=f"Could not run the check: {exc.__class__.__name__}.")

        reasons: list[str] = []
        if response.status_code == 451:
            reasons.append("HTTP 451 (unavailable for legal reasons)")

        def _private(host: str | None) -> bool:
            try:
                return bool(host) and ipaddress.ip_address(host).is_private
            except ValueError:
                return False

        location = response.headers.get("location", "")
        if response.is_redirect and _private(urlparse(location).hostname):
            reasons.append(f"redirect to a private address ({urlparse(location).hostname})")

        body = response.text[:4000].lower() if response.status_code < 400 else ""
        for match in re.finditer(r"<iframe[^>]+src=[\"']?([^\"'>\s]+)", body):
            if _private(urlparse(match.group(1)).hostname):
                reasons.append("page embeds an iframe from a private address")
                break

        if reasons:
            return CheckResult(
                name=name, status=Status.FAILED,
                message="Signs of a block page: " + "; ".join(reasons) + ".",
                details={"reasons": reasons, "suspected": True})
        return CheckResult(name=name, status=Status.OK,
                           message="No block page indicators in the plain HTTP response.",
                           details={"suspected": False})

    def _plain_http(self) -> CheckResult:
        self._report("Testing plain HTTP ...")
        start = time.perf_counter()
        try:
            resp = httpx.get(HTTP_TEST_URL_PLAIN, timeout=HTTP_TIMEOUT, follow_redirects=True)
            duration_ms = (time.perf_counter() - start) * 1000.0
            return CheckResult(
                name="Plain HTTP",
                status=Status.OK if resp.status_code < 400 else Status.WARNING,
                message=f"HTTP {resp.status_code} in {duration_ms:.0f} ms.",
                details={"status_code": resp.status_code, "url": str(resp.url)},
                duration_ms=duration_ms,
            )
        except httpx.HTTPError as exc:
            duration_ms = (time.perf_counter() - start) * 1000.0
            return CheckResult(
                name="Plain HTTP",
                status=Status.FAILED,
                message=f"Failed: {exc}",
                duration_ms=duration_ms,
            )

    def _https(self) -> CheckResult:
        self._report("Testing HTTPS ...")
        start = time.perf_counter()
        try:
            resp = httpx.get(HTTP_TEST_URL_TLS, timeout=HTTP_TIMEOUT, follow_redirects=True)
            duration_ms = (time.perf_counter() - start) * 1000.0
            return CheckResult(
                name="HTTPS",
                status=Status.OK if resp.status_code < 400 else Status.WARNING,
                message=f"HTTP {resp.status_code} in {duration_ms:.0f} ms.",
                details={"status_code": resp.status_code, "url": str(resp.url)},
                duration_ms=duration_ms,
            )
        except httpx.HTTPError as exc:
            duration_ms = (time.perf_counter() - start) * 1000.0
            return CheckResult(
                name="HTTPS",
                status=Status.FAILED,
                message=f"Failed: {exc}",
                duration_ms=duration_ms,
            )

    def _http2(self) -> CheckResult:
        self._report("Testing HTTP/2 ...")
        start = time.perf_counter()
        try:
            with httpx.Client(http2=True, timeout=HTTP_TIMEOUT) as client:
                resp = client.get(HTTP2_TEST_URL)
                duration_ms = (time.perf_counter() - start) * 1000.0
                negotiated = resp.http_version
                if negotiated == "HTTP/2":
                    return CheckResult(
                        name="HTTP/2 Support",
                        status=Status.OK,
                        message=f"Server negotiated HTTP/2 in {duration_ms:.0f} ms.",
                        details={"http_version": negotiated},
                        duration_ms=duration_ms,
                    )
                return CheckResult(
                    name="HTTP/2 Support",
                    status=Status.WARNING,
                    message=f"Connected, but negotiated {negotiated} instead of HTTP/2.",
                    details={"http_version": negotiated},
                    duration_ms=duration_ms,
                )
        except ImportError:
            return CheckResult(
                name="HTTP/2 Support",
                status=Status.UNKNOWN,
                message="The optional 'h2' package is not installed - HTTP/2 could not be tested.",
            )
        except httpx.HTTPError as exc:
            duration_ms = (time.perf_counter() - start) * 1000.0
            return CheckResult(
                name="HTTP/2 Support",
                status=Status.FAILED,
                message=f"Failed: {exc}",
                duration_ms=duration_ms,
            )

    def _http3_hint(self) -> CheckResult:
        self._report("Checking HTTP/3 (QUIC) support ...")
        try:
            return self._http3_real_handshake()
        except ImportError:
            return self._http3_altsvc_hint()

    def _http3_real_handshake(self) -> CheckResult:
        # Imported lazily: aioquic is an optional dependency. If it is not
        # installed this raises ImportError and we fall back to the
        # Alt-Svc header hint below.
        import asyncio

        from aioquic.asyncio.client import connect
        from aioquic.h3.connection import H3_ALPN
        from aioquic.quic.configuration import QuicConfiguration

        async def _try_connect() -> tuple[bool, float]:
            config = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN)
            config.verify_mode = 0  # do not fail on cert issues for this probe
            start = time.perf_counter()
            async with connect(HTTP3_TEST_HOST, 443, configuration=config) as client:
                await client.wait_connected()
            return True, (time.perf_counter() - start) * 1000.0

        try:
            success, duration_ms = asyncio.run(asyncio.wait_for(_try_connect(), timeout=6))
            return CheckResult(
                name="HTTP/3 (QUIC) Support",
                status=Status.OK,
                message=f"QUIC handshake with {HTTP3_TEST_HOST} succeeded in {duration_ms:.0f} ms.",
                duration_ms=duration_ms,
            )
        except Exception as exc:  # noqa: BLE001 - any QUIC failure means "not working"
            return CheckResult(
                name="HTTP/3 (QUIC) Support",
                status=Status.WARNING,
                message=f"QUIC handshake failed: {exc}",
            )

    def _http3_altsvc_hint(self) -> CheckResult:
        try:
            resp = httpx.get(HTTP_TEST_URL_TLS, timeout=HTTP_TIMEOUT)
            alt_svc = resp.headers.get("alt-svc", "")
            if "h3" in alt_svc:
                return CheckResult(
                    name="HTTP/3 (QUIC) Support",
                    status=Status.OK,
                    message="Server advertises HTTP/3 via Alt-Svc header (indirect hint, "
                    "QUIC handshake not performed - install 'aioquic' for a real test).",
                    details={"alt_svc": alt_svc},
                )
            return CheckResult(
                name="HTTP/3 (QUIC) Support",
                status=Status.UNKNOWN,
                message="Server did not advertise HTTP/3 via Alt-Svc "
                "(install 'aioquic' for a real QUIC handshake test).",
                details={"alt_svc": alt_svc},
            )
        except httpx.HTTPError as exc:
            return CheckResult(
                name="HTTP/3 (QUIC) Support",
                status=Status.UNKNOWN,
                message=f"Could not check Alt-Svc hint: {exc}",
            )

    def _redirect(self) -> CheckResult:
        self._report("Testing HTTP redirect handling ...")
        start = time.perf_counter()
        try:
            resp = httpx.get(REDIRECT_TEST_URL, timeout=HTTP_TIMEOUT, follow_redirects=True)
            duration_ms = (time.perf_counter() - start) * 1000.0
            redirected = len(resp.history) > 0
            return CheckResult(
                name="HTTP Redirect",
                status=Status.OK,
                message=(
                    f"Followed {len(resp.history)} redirect(s) to {resp.url}." if redirected
                    else "No redirect occurred; final response received directly."
                ),
                details={"redirect_count": len(resp.history), "final_url": str(resp.url)},
                duration_ms=duration_ms,
            )
        except httpx.HTTPError as exc:
            duration_ms = (time.perf_counter() - start) * 1000.0
            return CheckResult(
                name="HTTP Redirect",
                status=Status.FAILED,
                message=f"Failed: {exc}",
                duration_ms=duration_ms,
            )

    def _compression(self) -> CheckResult:
        self._report("Testing response compression ...")
        try:
            resp = httpx.get(
                HTTP_TEST_URL_TLS,
                timeout=HTTP_TIMEOUT,
                headers={"Accept-Encoding": "gzip, br, deflate"},
            )
            encoding = resp.headers.get("content-encoding")
            if encoding:
                return CheckResult(
                    name="Response Compression",
                    status=Status.OK,
                    message=f"Server compressed the response using '{encoding}'.",
                    details={"content_encoding": encoding},
                )
            return CheckResult(
                name="Response Compression",
                status=Status.WARNING,
                message="Server did not compress the response body.",
            )
        except httpx.HTTPError as exc:
            return CheckResult(
                name="Response Compression",
                status=Status.FAILED,
                message=f"Failed: {exc}",
            )

    def _connection_reuse(self) -> CheckResult:
        self._report("Testing TCP connection reuse (keep-alive) ...")
        # urllib3's pool counts how many TCP connections it really opened, so
        # two requests over exactly one connection is proof of reuse (not a guess).
        host = urlparse(HTTP_TEST_URL_TLS).hostname or "www.cloudflare.com"
        pool = urllib3.HTTPSConnectionPool(host, port=443, maxsize=1, timeout=HTTP_TIMEOUT)
        try:
            start = time.perf_counter()
            pool.request("GET", "/", retries=False)
            first_ms = (time.perf_counter() - start) * 1000.0
            start = time.perf_counter()
            pool.request("GET", "/", retries=False)
            second_ms = (time.perf_counter() - start) * 1000.0

            connections = pool.num_connections
            requests_made = pool.num_requests
            details = {
                "connections_opened": connections,
                "requests_made": requests_made,
                "first_request_ms": round(first_ms, 1),
                "second_request_ms": round(second_ms, 1),
            }
            if connections == 1 and requests_made == 2:
                return CheckResult(
                    name="Connection Reuse (Keep-Alive)",
                    status=Status.OK,
                    message=(
                        f"Two requests shared one TCP connection "
                        f"(first {first_ms:.0f} ms, second {second_ms:.0f} ms)."
                    ),
                    details=details,
                )
            return CheckResult(
                name="Connection Reuse (Keep-Alive)",
                status=Status.WARNING,
                message=(
                    f"The server or network closed the connection between requests "
                    f"({connections} connections opened for {requests_made} requests)."
                ),
                details=details,
            )
        except urllib3.exceptions.HTTPError as exc:
            return CheckResult(
                name="Connection Reuse (Keep-Alive)",
                status=Status.FAILED,
                message=f"Failed: {exc}",
            )
        finally:
            pool.close()
