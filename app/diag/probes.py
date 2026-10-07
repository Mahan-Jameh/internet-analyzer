"""
probes.py
=========
Shared low-level probes. One implementation of "resolve a name" and "connect
over TCP" so that no module duplicates timeout/error logic.

TCP connect semantics (documented here because they are easy to over-read):

    OPEN         the three-way handshake completed.
    CLOSED       the host answered with RST: something is reachable and nothing
                 listens on that port (or a firewall actively rejects it).
    RESET        the connection was torn down after it began (often a middlebox).
    TIMEOUT      no answer in time. This is NOT "closed": dropped packets, a
                 firewall, routing trouble and packet loss all look the same.
    UNREACHABLE  the local stack or a router reported network/host unreachable.

A connect scan can never prove that a port is *filtered*; a timeout is reported
as ``POSSIBLY_FILTERED`` / ``FILTERED_OR_UNREACHABLE`` with a confidence value.
"""

from __future__ import annotations

import ipaddress
import socket
import threading
import time
from dataclasses import dataclass

from app.diag.neterrors import NormalizedError, normalize_exception, normalize_os_error
from app.diag.results import RetryOutcome, TechnicalStatus, TestResult
from app.diag.retry import run_with_retry
from app.diag.testconfig import NetworkTestConfig
from app.logger import get_logger

log = get_logger(__name__)
_S = TechnicalStatus

FAMILY_NAMES = {socket.AF_INET: "IPv4", socket.AF_INET6: "IPv6"}


def is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def family_of_ip(ip: str) -> str:
    return "IPv6" if ":" in ip else "IPv4"


@dataclass
class Resolution:
    host: str
    ip: str | None
    family: str | None
    all_ips: list[str]
    duration_ms: float
    error: NormalizedError | None = None

    @property
    def ok(self) -> bool:
        return self.ip is not None


def resolve(host: str, family: str | None = None, port: int = 0) -> Resolution:
    """
    Resolve ``host`` via the system resolver. ``family`` ("IPv4"/"IPv6") limits the
    lookup; None prefers IPv4 (what the previous scanner used) but accepts IPv6.
    """
    start = time.perf_counter()
    if is_ip_literal(host):
        ip = host.strip("[]")
        fam = family_of_ip(ip)
        if family and fam != family:
            err = normalize_os_error(10047, f"{host} is not an {family} address")
            return Resolution(host, None, None, [], 0.0, err)
        return Resolution(host, ip, fam, [ip], 0.0)
    af = {"IPv4": socket.AF_INET, "IPv6": socket.AF_INET6}.get(family or "", socket.AF_UNSPEC)
    try:
        infos = socket.getaddrinfo(host, port or None, af, socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError, OSError) as exc:
        return Resolution(host, None, None, [], (time.perf_counter() - start) * 1000.0,
                          normalize_exception(exc))
    ips: list[str] = []
    for info in infos:
        ip = info[4][0]
        if ip not in ips:
            ips.append(ip)
    ips.sort(key=lambda a: ":" in a)                 # IPv4 first when family is unspecified
    ip = ips[0] if ips else None
    return Resolution(host, ip, family_of_ip(ip) if ip else None, ips,
                      (time.perf_counter() - start) * 1000.0,
                      None if ip else normalize_os_error(11004, "no address returned"))


def dns_failure_result(test_id: str, host: str, res: Resolution, role: str = "system",
                       timeout_ms: int | None = None) -> TestResult:
    err = res.error
    r = TestResult(
        test_id=test_id, category="dns_resolution", status=_S.DNS_FAILED, target=host,
        protocol="DNS", duration_ms=res.duration_ms, timeout_ms=timeout_ms,
        error_type=err.error_type if err else None, error_code=err.error_code if err else None,
        platform_error=err.platform_error if err else None,
        error_message=err.error_message if err else None, recoverable=err.recoverable if err else None,
        summary=f"Could not resolve {host}: {err.error_message if err else 'no answer'}",
        metadata={"role": role, "domain": host},
    )
    r.add_evidence(f"System resolver returned {err.error_code if err else 'no data'} for {host}")
    return r


def tcp_attempt(ip: str, port: int, timeout: float) -> tuple[NormalizedError | None, float, str | None]:
    """One TCP connect. Returns (error or None, elapsed_ms, local address)."""
    af = socket.AF_INET6 if ":" in ip else socket.AF_INET
    start = time.perf_counter()
    local: str | None = None
    try:
        with socket.socket(af, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            code = sock.connect_ex((ip, port))
            elapsed = (time.perf_counter() - start) * 1000.0
            if code == 0:
                try:
                    local = sock.getsockname()[0]
                except OSError:
                    local = None
                return None, elapsed, local
            return normalize_os_error(code), elapsed, None
    except (socket.timeout, TimeoutError) as exc:
        return normalize_exception(exc), (time.perf_counter() - start) * 1000.0, None
    except OSError as exc:
        return normalize_exception(exc), (time.perf_counter() - start) * 1000.0, None


def _tcp_summary(res: TestResult) -> str:
    where = f"{res.target}:{res.port}" if res.target else f"port {res.port}"
    ms = f" in {res.duration_ms:.0f} ms" if res.duration_ms is not None else ""
    return {
        _S.OPEN: f"Connection to {where} succeeded{ms}.",
        _S.CLOSED: f"{where} actively refused the connection (reachable, nothing accepting connections).",
        _S.TIMEOUT: f"{where}: no response within {((res.timeout_ms or 0) / 1000):.1f} s; "
                    "state is inconclusive, the port may be filtered.",
        _S.RESET: f"{where}: the connection was reset.",
        _S.UNREACHABLE: f"{where}: network or host unreachable.",
        _S.ERROR: f"{where}: local socket error ({res.error_message}).",
    }.get(res.status, f"{where}: {res.status.value}")


def tcp_probe(
    host: str,
    port: int,
    cfg: NetworkTestConfig,
    *,
    family: str | None = None,
    resolution: Resolution | None = None,
    role: str = "reachability",
    test_id: str | None = None,
    cancel: threading.Event | None = None,
    retry: bool = True,
) -> TestResult:
    """Resolve (unless a resolution is given) and TCP-connect, with selective retry."""
    tid = test_id or f"tcp.{host}.{port}"
    res = resolution or resolve(host, family)
    if not res.ok:
        r = dns_failure_result(f"dns.{host}", host, res, timeout_ms=int(cfg.dns_timeout * 1000))
        r.metadata["blocks"] = tid
        return r

    def attempt(n: int) -> TestResult:
        err, elapsed, local = tcp_attempt(res.ip or "", port, cfg.connect_timeout)
        out = TestResult(
            test_id=tid, category="tcp", target=host, resolved_ip=res.ip, address_family=res.family,
            protocol="TCP", port=port, duration_ms=elapsed, timeout_ms=cfg.connect_timeout_ms,
            metadata={"role": role, "target_is_ip": is_ip_literal(host), "attempt": n},
        )
        if err is None:
            out.status = _S.OPEN
            out.metadata["local_address"] = local
            out.add_evidence(f"TCP handshake to {res.ip}:{port} completed in {elapsed:.0f} ms")
        else:
            out.status = err.status
            out.error_type, out.error_code = err.error_type, err.error_code
            out.platform_error, out.error_message = err.platform_error, err.error_message
            out.recoverable = err.recoverable
            out.metadata["platform_error_name"] = err.platform_name
            out.add_evidence(f"connect() to {res.ip}:{port} ended with {err.error_code}"
                             + (f" ({err.platform_name})" if err.platform_name else ""))
        _label_tcp(out)
        out.summary = _tcp_summary(out)
        log.info("TCP TEST target=%s ip=%s family=%s port=%s attempt=%s timeout=%.1fs result=%s duration=%.0fms",
                 host, res.ip, res.family, port, n, cfg.connect_timeout, out.status.value, elapsed)
        return out

    if not retry:
        return attempt(1)
    return run_with_retry(attempt, cfg.retry, cancel)


def _label_tcp(out: TestResult) -> None:
    """Interpretation layer for a single TCP result (raw status stays untouched)."""
    if out.status is _S.TIMEOUT:
        out.interpretation, out.confidence = "FILTERED_OR_UNREACHABLE", 0.4
    elif out.status is _S.CLOSED:
        out.interpretation, out.confidence = "ACTIVELY_REFUSED", 0.9
    elif out.status is _S.RESET:
        out.interpretation, out.confidence = "RESET_BY_PEER_OR_MIDDLEBOX", 0.5
    elif out.status is _S.UNREACHABLE:
        out.interpretation, out.confidence = "NO_ROUTE", 0.8


def refine_timeouts(results: list[TestResult]) -> None:
    """
    Raise the confidence of 'possibly filtered' when other ports of the same host
    answered: the host is demonstrably up, so silence on one port is more likely a
    filter than an outage. Without such evidence it stays 'filtered or unreachable'.
    """
    by_ip: dict[str | None, list[TestResult]] = {}
    for r in results:
        by_ip.setdefault(r.resolved_ip, []).append(r)
    for group in by_ip.values():
        host_up = any(r.status in (_S.OPEN, _S.CLOSED) for r in group)
        for r in group:
            if r.status is not _S.TIMEOUT:
                continue
            if host_up:
                r.interpretation, r.confidence = "POSSIBLY_FILTERED", 0.75
                r.add_evidence("Other ports on the same address answered, so the host is up.")
            if r.retry_outcome is RetryOutcome.PERSISTENT_FAILURE and r.confidence:
                r.confidence = round(min(0.9, r.confidence + 0.1), 2)
