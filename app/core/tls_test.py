"""
tls_test.py
===========
Real TLS handshakes, reported *by phase* so a failure says exactly where it happened:

    DNS resolution -> TCP connect -> TLS handshake (ClientHello..Finished) -> certificate

Possible outcomes are specific (``DNS_FAILED``, a TCP error, ``TLS_HANDSHAKE_TIMEOUT``,
``TLS_HANDSHAKE_RESET``, ``TLS_PROTOCOL_ERROR``, ``CERTIFICATE_ERROR``,
``CERTIFICATE_HOSTNAME_MISMATCH``, success) - never one generic "TLS failed".

The SNI probe contacts ONE server address with different server names *and without any
SNI*. A handshake that works without SNI (or for other names) but is cut for the real name
is evidence of name-based interference; it is reported as evidence with a confidence, not
as a fact.
"""

from __future__ import annotations

import socket
import ssl
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Any, Callable, Optional

from app.constants import SNI_PROBE_BASELINE_HOST, SNI_PROBE_NAMES, TLS_TEST_HOSTS, TLS_TEST_PORT
from app.diag.adapter import check_from_result
from app.diag.neterrors import normalize_exception, normalize_os_error
from app.diag.probes import dns_failure_result, is_ip_literal, resolve
from app.diag.results import RetryOutcome, Severity, TechnicalStatus, TestResult
from app.diag.retry import run_with_retry
from app.diag.testconfig import DEFAULT_CONFIG, NetworkTestConfig
from app.logger import get_logger
from app.models import CheckResult, ModuleReport, Status
from app.utils.helpers import resolve_host

log = get_logger(__name__)
_S = TechnicalStatus

ProgressCallback = Optional[Callable[[str], None]]

HOSTNAME_MISMATCH_VERIFY_CODE = 62      # X509_V_ERR_HOSTNAME_MISMATCH


def classify_handshake_exception(exc: BaseException) -> tuple[TechnicalStatus, str, str]:
    """Map an exception raised *during* the handshake to (status, error_code, message)."""
    if isinstance(exc, ssl.SSLCertVerificationError):
        message = getattr(exc, "verify_message", "") or str(exc)
        if getattr(exc, "verify_code", None) == HOSTNAME_MISMATCH_VERIFY_CODE or "hostname mismatch" in str(exc).lower():
            return _S.TLS_FAILED, "CERTIFICATE_HOSTNAME_MISMATCH", message
        return _S.TLS_FAILED, "CERTIFICATE_ERROR", message
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return _S.TIMEOUT, "TLS_HANDSHAKE_TIMEOUT", "no handshake answer within the time limit"
    if isinstance(exc, ConnectionResetError):
        return _S.RESET, "TLS_HANDSHAKE_RESET", "connection reset during the handshake"
    if isinstance(exc, (ssl.SSLEOFError, ssl.SSLZeroReturnError)):
        return _S.TLS_FAILED, "TLS_HANDSHAKE_EOF", "the peer closed the connection during the handshake"
    if isinstance(exc, ssl.SSLError):
        return _S.TLS_FAILED, "TLS_PROTOCOL_ERROR", str(exc)[:200]
    if isinstance(exc, OSError):
        norm = normalize_exception(exc)
        if norm.status is _S.RESET:
            return _S.RESET, "TLS_HANDSHAKE_RESET", norm.error_message
        return norm.status, norm.error_code, norm.error_message
    norm = normalize_exception(exc)
    return norm.status, norm.error_code, norm.error_message


def _cert_info(cert: dict[str, Any] | None) -> dict[str, Any]:
    if not cert:
        return {"certificate_present": False}
    info: dict[str, Any] = {"certificate_present": True}
    for key in ("subject", "issuer"):
        parts = cert.get(key) or ()
        info[f"cert_{key}"] = ", ".join("=".join(kv) for rdn in parts for kv in rdn)
    not_after = cert.get("notAfter")
    if not_after:
        try:
            expires = datetime.fromtimestamp(ssl.cert_time_to_seconds(not_after), tz=timezone.utc)
            info["cert_not_after"] = expires.isoformat()
            info["cert_days_left"] = (expires - datetime.now(timezone.utc)).days
        except (ValueError, OverflowError):
            pass
    sans = [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"]
    if sans:
        info["cert_san_count"] = len(sans)
    return info


class TLSTester:
    def __init__(self, hosts: Optional[list[str]] = None, progress_cb: ProgressCallback = None,
                 config: NetworkTestConfig = DEFAULT_CONFIG, cancel: Optional[threading.Event] = None,
                 port: int = TLS_TEST_PORT, ca_file: Optional[str] = None) -> None:
        self.hosts = hosts or list(TLS_TEST_HOSTS)
        self.progress_cb = progress_cb
        self.config = config
        self.cancel = cancel or threading.Event()
        self.port = port
        self.ca_file = ca_file

    def _report(self, message: str) -> None:
        if self.progress_cb:
            self.progress_cb(message)
        log.info(message)

    # ------------------------------------------------------------------ #
    def _context(self, min_v: ssl.TLSVersion, max_v: ssl.TLSVersion, verify: bool,
                 alpn: Optional[list[str]]) -> ssl.SSLContext:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version, ctx.maximum_version = min_v, max_v
        if verify:
            ctx.check_hostname, ctx.verify_mode = True, ssl.CERT_REQUIRED
            ctx.load_default_certs()
            if self.ca_file:
                ctx.load_verify_locations(self.ca_file)
        else:
            ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
        if alpn:
            ctx.set_alpn_protocols(alpn)
        return ctx

    def handshake_phases(self, host: str, *args: Any, **kw: Any) -> TestResult:
        started = time.perf_counter()
        res = self._handshake_phases(host, *args, **kw)
        if res.duration_ms is None:
            res.duration_ms = (time.perf_counter() - started) * 1000.0
        return res

    def _handshake_phases(self, host: str, min_v: ssl.TLSVersion, max_v: ssl.TLSVersion, *, verify: bool = True,
                         alpn: Optional[list[str]] = None, sni: Optional[str] | bool = True,
                         ip: Optional[str] = None, test_id: Optional[str] = None,
                         role: str = "handshake") -> TestResult:
        """One handshake attempt, phase by phase. ``sni=True`` sends ``host``; ``None`` sends no SNI."""
        tid = test_id or f"tls.{host}"
        timeout = self.config.tls_timeout
        version_label = {ssl.TLSVersion.TLSv1_3: "1.3", ssl.TLSVersion.TLSv1_2: "1.2"}.get(min_v, "?")
        res = TestResult(tid, "tls", target=host, protocol="TLS", port=self.port,
                         timeout_ms=int(timeout * 1000), metadata={"role": role, "tls_version_tested": version_label},
                         metrics={})
        # ---- phase 1: DNS ------------------------------------------------
        if ip is None:
            resolution = resolve(host, "IPv4" if not is_ip_literal(host) else None)
            res.metrics["dns_ms"] = round(resolution.duration_ms, 1)
            if not resolution.ok:
                failed = dns_failure_result(tid, host, resolution)
                res.status, res.error_code, res.error_type = _S.DNS_FAILED, failed.error_code, failed.error_type
                res.error_message, res.interpretation = failed.error_message, "DNS_FAILED"
                res.metadata["phase"] = "dns"
                res.summary = f"{host}: DNS resolution failed, the TLS test could not start."
                return res
            ip = resolution.ip
        res.resolved_ip = ip
        res.address_family = "IPv6" if ip and ":" in ip else "IPv4"

        # ---- phase 2: TCP ---------------------------------------------------
        af = socket.AF_INET6 if ":" in (ip or "") else socket.AF_INET
        t0 = time.perf_counter()
        sock = socket.socket(af, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            code = sock.connect_ex((ip, self.port))
        except OSError as exc:
            sock.close()
            norm = normalize_exception(exc)
            code, err = -1, norm
        else:
            err = normalize_os_error(code) if code else None
        res.metrics["tcp_ms"] = round((time.perf_counter() - t0) * 1000.0, 1)
        if err is not None:
            sock.close()
            res.status = err.status if err.status is not _S.CLOSED else _S.CLOSED
            res.error_type, res.error_code, res.error_message = err.error_type, err.error_code, err.error_message
            res.platform_error, res.recoverable = err.platform_error, err.recoverable
            res.interpretation = "TCP_FAILED"
            res.metadata["phase"] = "tcp"
            res.summary = f"{host}: the TCP connection to port {self.port} failed ({err.error_code}); TLS could not start."
            res.add_evidence(f"TCP connect to {ip}:{self.port} ended with {err.error_code}")
            return res
        res.metadata["tcp_ok"] = True

        # ---- phase 3+4: ClientHello / handshake / certificate ---------------------
        server_name = None if sni is None else (host if sni is True else str(sni))
        t1 = time.perf_counter()
        try:
            ctx = self._context(min_v, max_v, verify, alpn)
            with ctx.wrap_socket(sock, server_hostname=server_name) as tls_sock:
                res.metrics["handshake_ms"] = round((time.perf_counter() - t1) * 1000.0, 1)
                res.metrics.update(tls_version=tls_sock.version(), alpn=tls_sock.selected_alpn_protocol())
                cipher = tls_sock.cipher()
                res.metrics["cipher"] = list(cipher) if cipher else None
                res.metrics.update(_cert_info(tls_sock.getpeercert() if verify else None))
            res.status = _S.SUCCESS
            res.metrics["hostname_match"] = bool(verify)
            res.summary = (f"{host}: TLS {res.metrics['tls_version']} handshake completed in "
                           f"{res.metrics['handshake_ms']:.0f} ms.")
            res.add_evidence(f"Handshake completed ({res.metrics['tls_version']}, "
                             f"{cipher[0] if cipher else 'unknown cipher'})")
        except Exception as exc:  # noqa: BLE001 - classified below, never swallowed silently
            sock.close()
            res.metrics["handshake_ms"] = round((time.perf_counter() - t1) * 1000.0, 1)
            status, code_name, message = classify_handshake_exception(exc)
            res.status, res.error_code, res.error_message = status, code_name, message
            res.error_type = type(exc).__name__
            res.platform_error = getattr(exc, "errno", None)
            res.metadata["phase"] = "certificate" if code_name.startswith("CERTIFICATE") else "handshake"
            res.interpretation = code_name
            res.summary = f"{host}: {code_name.replace('_', ' ').lower()} ({message})."
            res.add_evidence(f"TCP/{self.port} succeeded, then the TLS phase failed with {code_name}")
            log.debug("TLS handshake failure for %s: %r", host, exc)
        log.info("TLS TEST target=%s ip=%s version=%s sni=%s timeout=%.1fs result=%s code=%s",
                 host, ip, version_label, server_name, timeout, res.status.value, res.error_code)
        return res

    def _handshake_retrying(self, host: str, min_v: ssl.TLSVersion, max_v: ssl.TLSVersion, **kw: Any) -> TestResult:
        return run_with_retry(lambda n: self.handshake_phases(host, min_v, max_v, **kw), self.config.retry, self.cancel)

    # ------------------------------------------------------------------ #
    def run_all(self) -> ModuleReport:
        report = ModuleReport(module_name="TLS Test")
        jobs: list[tuple[str, str]] = [(h, v) for h in self.hosts for v in ("1.3", "1.2")]
        versions = {"1.3": ssl.TLSVersion.TLSv1_3, "1.2": ssl.TLSVersion.TLSv1_2}
        with ThreadPoolExecutor(max_workers=max(1, min(len(jobs), self.config.max_concurrency)),
                                thread_name_prefix="icpa-tls") as pool:
            futs = {}
            for host, ver in jobs:
                self._report(f"Testing TLS {ver} with {host} ...")
                futs[(host, ver)] = pool.submit(
                    self._safe_handshake, host, versions[ver],
                    test_id=f"tls.{host}.{ver}", alpn=["h2", "http/1.1"] if ver == "1.3" else None)
            handshakes = {k: f.result() for k, f in futs.items()}

        for host in self.hosts:
            r13, r12 = handshakes[(host, "1.3")], handshakes[(host, "1.2")]
            for ver, res in (("1.3", r13), ("1.2", r12)):
                if not res.ok:   # one TLS version failing while the other works is only a warning
                    res.severity = Severity.WARNING if (r13.ok or r12.ok) else Severity.ERROR
                    if res.error_code == "CERTIFICATE_ERROR" or res.error_code == "CERTIFICATE_HOSTNAME_MISMATCH":
                        res.severity = Severity.ERROR
                report.results.append(res)
                msg = res.summary
                if res.ok:
                    msg = f"Success in {res.metrics.get('handshake_ms', 0):.0f} ms. Cipher: {tuple(res.metrics['cipher']) if res.metrics.get('cipher') else None}"
                details = {"version": res.metrics.get("tls_version"), "cipher": res.metrics.get("cipher"),
                           "alpn_selected": res.metrics.get("alpn"), "tcp_connected": bool(res.metadata.get("tcp_ok")),
                           "phase": res.metadata.get("phase"), **{k: v for k, v in res.metrics.items()
                                                                  if k.startswith("cert_")}}
                report.add(check_from_result(f"TLS {ver} Handshake ({host})", res, message=msg, details=details))
            report.add(self._certificate_check(host, r13, r12, report))
            self._derived_checks(host, r13, r12, report)

        report.add(self._sni_filtering_probe(report))
        report.finish()
        return report

    def _safe_handshake(self, host: str, version: ssl.TLSVersion, **kw: Any) -> TestResult:
        try:
            return self._handshake_retrying(host, version, version, **kw)
        except Exception as exc:  # noqa: BLE001 - one handshake must not break the module
            log.exception("TLS handshake test for %s crashed", host)
            return TestResult(kw.get("test_id", f"tls.{host}"), "tls", status=_S.ERROR, target=host,
                              error_type=type(exc).__name__, error_message=str(exc)[:200],
                              metadata={"role": "handshake"}, summary=f"{host}: the TLS test could not be completed.")

    def _certificate_check(self, host: str, r13: TestResult, r12: TestResult, report: ModuleReport) -> CheckResult:
        ok = r13 if r13.ok else r12 if r12.ok else None
        res = TestResult(f"tls.{host}.certificate", "tls", target=host, protocol="TLS", port=self.port,
                         metadata={"role": "certificate"})
        if ok is not None:
            res.status = _S.SUCCESS
            res.metrics = {k: v for k, v in ok.metrics.items() if k.startswith("cert_")}
            res.summary = "Certificate chain validated successfully by the OS trust store."
            days = res.metrics.get("cert_days_left")
            if isinstance(days, int) and days < 14:
                res.warnings.append(f"The certificate expires in {days} day(s).")
        else:
            cert_failure = next((r for r in (r13, r12) if (r.error_code or "").startswith("CERTIFICATE")), None)
            if cert_failure:
                res.status, res.error_code = _S.TLS_FAILED, cert_failure.error_code
                res.error_message = cert_failure.error_message
                res.summary = f"Certificate problem: {cert_failure.error_message}"
            else:
                res.status, res.severity = _S.INCONCLUSIVE, Severity.ERROR
                res.summary = "Could not complete a validated handshake to check the certificate."
        report.results.append(res)
        return check_from_result(f"Certificate Validation ({host})", res)

    def _derived_checks(self, host: str, r13: TestResult, r12: TestResult, report: ModuleReport) -> None:
        ok13, ok12 = r13.ok, r12.ok
        best = r13 if ok13 else r12
        sni = TestResult(f"tls.{host}.sni", "tls", target=host, protocol="TLS", metadata={"role": "sni_support"})
        if ok13 or ok12:
            sni.status = _S.SUCCESS
            sni.summary = "Server returned a certificate matching the requested SNI name."
        else:
            sni.status, sni.severity = _S.INCONCLUSIVE, Severity.WARNING
            sni.summary = "SNI support could not be confirmed because no handshake completed."
        report.results.append(sni)
        report.add(check_from_result(f"SNI Support ({host})", sni))
        if not (ok13 or ok12):
            return
        alpn = best.metrics.get("alpn")
        alpn_res = TestResult(f"tls.{host}.alpn", "tls", target=host, protocol="TLS",
                              metadata={"role": "alpn"}, metrics={"alpn_selected": alpn})
        if ok13 and alpn:
            alpn_res.status, alpn_res.summary = _S.SUCCESS, f"Server selected '{alpn}' via ALPN."
        else:
            alpn_res.status, alpn_res.severity = _S.INCONCLUSIVE, Severity.WARNING
            alpn_res.summary = "No ALPN protocol was negotiated (HTTP/2 cannot be used on this path)."
        report.results.append(alpn_res)
        report.add(check_from_result(f"ALPN Negotiation ({host})", alpn_res, details={"alpn_selected": alpn}))
        cipher = best.metrics.get("cipher")
        if cipher:
            c = TestResult(f"tls.{host}.cipher", "tls", target=host, protocol="TLS", status=_S.SUCCESS,
                           metadata={"role": "cipher"}, metrics={"cipher": cipher})
            c.summary = f"{cipher[0]} ({cipher[1]}, {cipher[2]} bits)"
            report.results.append(c)
            report.add(check_from_result(f"Cipher Suite ({host})", c, details={"cipher": list(cipher)}))

    # ------------------------------------------------------------------ #
    def _probe_sni(self, ip: str, sni: Optional[str]) -> str:
        """
        Handshake with ``ip`` presenting ``sni`` (``None`` = no SNI extension). Returns one of:
        ok / reset / eof / timeout / alert / error. Certificate checks are off on purpose: only
        the *behaviour* of the connection matters, not who the server claims to be.
        """
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((ip, self.port), timeout=self.config.tls_timeout) as sock:
                with context.wrap_socket(sock, server_hostname=sni):
                    return "ok"
        except ConnectionResetError:
            return "reset"
        except ssl.SSLEOFError:
            return "eof"          # peer closed mid-handshake, typical of an injected RST/FIN
        except ssl.SSLError:
            return "alert"        # the server itself answered with a TLS alert: not a block
        except (socket.timeout, TimeoutError):
            return "timeout"
        except OSError:
            return "error"

    def _confirmed_probe(self, ip: str, sni: Optional[str]) -> str:
        """A 'bad' outcome is repeated once: a single cut can be ordinary packet loss."""
        first = self._probe_sni(ip, sni)
        if first in ("reset", "eof", "timeout") and not self.cancel.is_set():
            second = self._probe_sni(ip, sni)
            return first if second == first else second
        return first

    def _sni_filtering_probe(self, report: Optional[ModuleReport] = None) -> CheckResult:
        """
        Contact ONE server IP with several different SNI names and with no SNI at all. Different
        outcomes for the same address point to a decision based on the name, not the address.
        """
        self._report("Probing for SNI-based filtering ...")
        start = time.perf_counter()
        res = TestResult("tls.sni_probe", "tls", target=SNI_PROBE_BASELINE_HOST, protocol="TLS", port=self.port,
                         metadata={"role": "sni_probe"})
        ips = resolve_host(SNI_PROBE_BASELINE_HOST, family=socket.AF_INET)
        if not ips:
            res.status, res.interpretation = _S.INCONCLUSIVE, "DNS_FAILED"
            res.summary = "Could not resolve the probe server, so SNI filtering could not be tested."
            if report is not None:
                report.results.append(res)
            return check_from_result("SNI Filtering Probe", res)

        ip = ips[0]
        res.resolved_ip = ip
        names: list[Optional[str]] = [*SNI_PROBE_NAMES, None]       # None = handshake without SNI
        with ThreadPoolExecutor(max_workers=len(names), thread_name_prefix="icpa-sni") as pool:
            outcomes_list = list(pool.map(lambda n: self._confirmed_probe(ip, n), names))
        outcomes = {(n or "(no SNI)"): o for n, o in zip(names, outcomes_list)}
        res.duration_ms = (time.perf_counter() - start) * 1000.0

        good = {"ok", "alert"}      # the server answered, so the path is not blocking this name
        bad = {"reset", "eof", "timeout"}
        passed = [s for s, o in outcomes.items() if o in good]
        blocked = [s for s, o in outcomes.items() if o in bad]
        res.metrics = {"server_ip": ip, "outcomes": outcomes}
        details = {"server_ip": ip, "outcomes": outcomes, "suspected": False}
        res.add_evidence(f"TCP/{self.port} to {ip} is reachable" if passed else f"No handshake to {ip} completed")
        for name, outcome in outcomes.items():
            res.add_evidence(f"Handshake with {name}: {outcome}")

        if blocked and passed:
            details["suspected"] = True
            conf = 0.65 + (0.1 if "(no SNI)" in passed and SNI_PROBE_BASELINE_HOST in blocked else 0.0)
            res.status, res.severity = _S.TLS_FAILED, Severity.WARNING
            res.interpretation, res.confidence = "SNI_SELECTIVE_FAILURE", round(min(conf, 0.85), 2)
            res.summary = ("Same server, different outcomes: handshakes were cut for " + ", ".join(blocked)
                           + " but worked for " + ", ".join(passed)
                           + ". This pattern is consistent with SNI-based filtering, though it is not proof.")
        elif blocked:
            res.status, res.severity = _S.TLS_FAILED, Severity.ERROR
            res.interpretation = "ADDRESS_OR_TLS_WIDE_FAILURE"
            res.summary = (f"Every handshake to {ip} failed regardless of SNI name, so this looks like a general "
                           "block of that address or of TLS, not SNI filtering.")
        elif not passed:
            res.status, res.interpretation = _S.INCONCLUSIVE, "NO_HANDSHAKE_COMPLETED"
            res.summary = ("No handshake could be completed for any name, so SNI filtering could not be assessed.")
        else:
            res.status = _S.SUCCESS
            res.summary = "Handshakes behaved the same for every SNI name tested."
        if report is not None:
            report.results.append(res)
        return check_from_result("SNI Filtering Probe", res, details=details)
