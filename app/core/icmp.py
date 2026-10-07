"""
icmp.py
=======
Ping through the system ``ping`` command (no raw sockets, no admin rights),
returning normalized results.

Ping is *one* transport signal. A failed ping is reported as
``ICMP_BLOCKED_OR_UNAVAILABLE`` (or an explicit unreachable error when an
intermediate device said so) - never as "the Internet is down".
"""

from __future__ import annotations

import re
import statistics
import threading
import time
from dataclasses import dataclass, field

from app.diag.results import Severity, TechnicalStatus, TestResult
from app.diag.testconfig import DEFAULT_CONFIG, NetworkTestConfig
from app.logger import get_logger
from app.utils.helpers import IS_WINDOWS, parse_ping_rtts, run_subprocess

log = get_logger(__name__)
_S = TechnicalStatus

_IP_IN_LINE = re.compile(r"(?<![\w.:])((?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{0,4}){2,7})(?![\w.])")
_BRACKET_IP = re.compile(r"\[[0-9a-fA-F:.]+\]")


@dataclass
class PingOutput:
    sent: int
    rtts: list[float]
    code: int
    raw: str
    error_hint: str | None = None            # "NETWORK_UNREACHABLE" | "HOST_UNREACHABLE" | "NO_PING_COMMAND" | None
    reporter_ip: str | None = None           # device that sent an error reply, if any
    duration_ms: float = 0.0
    extra: dict[str, object] = field(default_factory=dict)

    @property
    def received(self) -> int:
        return len(self.rtts)


def build_ping_args(host: str, count: int, timeout_s: float, family: str | None = None,
                    df_size: int | None = None, interval_s: float | None = None) -> list[str]:
    fam = ["-4"] if family == "IPv4" else ["-6"] if family == "IPv6" else []
    if IS_WINDOWS:
        args = ["ping", *fam, "-n", str(count), "-w", str(int(timeout_s * 1000))]
        if df_size is not None:
            args += ["-f", "-l", str(df_size)]
        return [*args, host]
    args = ["ping", *fam, "-c", str(count), "-W", str(max(1, int(round(timeout_s))))]
    if interval_s is not None and interval_s >= 0.2:
        args += ["-i", str(interval_s)]
    if df_size is not None:
        args += ["-M", "do", "-s", str(df_size)]
    return [*args, host]


def find_error_reporter(output: str, host: str) -> str | None:
    """
    Language independent: a router that rejects a probe sends a line such as
    "Reply from 192.168.1.1: Destination host unreachable" - an address but no
    ``TTL=`` and no ``ms``. Header/summary lines mention the target and are skipped.
    """
    for line in output.splitlines():
        low = line.lower()
        if "ttl=" in low or "ms" in low or host.lower() in low or _BRACKET_IP.search(line):
            continue
        m = _IP_IN_LINE.search(line)
        if m and m.group(1) != host:
            return m.group(1)
    return None


def run_ping(host: str, count: int, timeout_s: float, *, family: str | None = None,
             df_size: int | None = None, interval_s: float | None = None) -> PingOutput:
    start = time.perf_counter()
    args = build_ping_args(host, count, timeout_s, family, df_size, interval_s)
    code, out, err = run_subprocess(args, timeout=timeout_s * count + 6)
    rtts = parse_ping_rtts(out)
    hint: str | None = None
    reporter = None
    if code == -2:
        hint = "NO_PING_COMMAND"
    elif not rtts:
        reporter = find_error_reporter(out, host)
        low = (out + err).lower()
        if "network is unreachable" in low or "network unreachable" in low:
            hint = "NETWORK_UNREACHABLE"
        elif reporter or "unreachable" in low:
            hint = "HOST_UNREACHABLE"
    return PingOutput(count, rtts, code, (out.strip() or err.strip()), hint, reporter,
                      (time.perf_counter() - start) * 1000.0)


def latency_stats(rtts: list[float], sent: int) -> dict[str, float | int | None]:
    received = len(rtts)
    loss = 100.0 * (sent - received) / sent if sent else 100.0
    if not rtts:
        return {"packets_sent": sent, "packets_received": 0, "packet_loss_percent": round(loss, 1),
                "min_ms": None, "average_ms": None, "median_ms": None, "max_ms": None, "jitter_ms": None}
    # Jitter = mean absolute difference between consecutive replies (RFC 3550 style).
    diffs = [abs(b - a) for a, b in zip(rtts, rtts[1:])]
    return {
        "packets_sent": sent, "packets_received": received, "packet_loss_percent": round(loss, 1),
        "min_ms": round(min(rtts), 1), "average_ms": round(statistics.mean(rtts), 1),
        "median_ms": round(statistics.median(rtts), 1), "max_ms": round(max(rtts), 1),
        "jitter_ms": round(statistics.mean(diffs), 1) if diffs else 0.0,
    }


def ping_result(host: str, count: int = 4, cfg: NetworkTestConfig = DEFAULT_CONFIG, *,
                family: str | None = None, test_id: str | None = None, role: str = "internet",
                runner=run_ping) -> TestResult:  # noqa: ANN001 - injectable for tests
    """Ping ``host`` and return a normalized ICMP result."""
    out: PingOutput = runner(host, count, cfg.ping_timeout, family=family)
    res = TestResult(test_id or f"icmp.{host}", "icmp", target=host, protocol="ICMP",
                     duration_ms=out.duration_ms, timeout_ms=int(cfg.ping_timeout * 1000),
                     metrics=latency_stats(out.rtts, count), metadata={"role": role})
    res.metadata["raw_output"] = out.raw[-2000:]
    if out.received:
        loss = float(res.metrics["packet_loss_percent"] or 0.0)
        res.status = _S.SUCCESS if loss == 0 else _S.PARTIAL
        res.severity = Severity.OK if loss == 0 else Severity.WARNING
        res.interpretation = "ICMP_AVAILABLE"
        res.summary = (f"Ping {host}: reachable, average {res.metrics['average_ms']} ms."
                       if loss == 0 else f"Ping {host}: {loss:.0f}% packet loss.")
        res.add_evidence(f"{out.received} of {count} echo replies received")
        return res

    # Nothing came back. Say what we can prove and no more.
    if out.error_hint == "NO_PING_COMMAND":
        res.status, res.severity = _S.ERROR, Severity.INFO
        res.error_code = "NO_PING_COMMAND"
        res.summary = "The system ping command is not available, so ICMP could not be tested."
    elif out.error_hint in ("NETWORK_UNREACHABLE", "HOST_UNREACHABLE"):
        res.status, res.severity = _S.UNREACHABLE, Severity.WARNING
        res.error_code = out.error_hint
        res.interpretation = out.error_hint
        res.summary = f"Ping {host}: {out.error_hint.replace('_', ' ').lower()}" + (
            f" (reported by {out.reporter_ip})." if out.reporter_ip else ".")
        res.add_evidence(f"An ICMP error was returned{' by ' + out.reporter_ip if out.reporter_ip else ''}")
    else:
        res.status, res.severity = _S.TIMEOUT, Severity.WARNING
        res.error_code = "TIMEOUT"
        res.interpretation, res.confidence = "ICMP_BLOCKED_OR_UNAVAILABLE", 0.5
        res.summary = (f"Ping {host}: no reply. ICMP echo may be blocked or the host may not answer ping; "
                       "this does not by itself mean there is no Internet access.")
        res.add_evidence(f"0 of {count} echo replies received and no ICMP error")
    return res
