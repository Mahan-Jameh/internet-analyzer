"""
latency_test.py
================
Measures latency with several probes per target and reports real statistics:
packets sent/received, loss %, min / average / median / max and jitter.

What was measured is always stated: ICMP echo normally; if ICMP gets no reply
at all the module falls back to timing TCP handshakes on port 443 (marked as
``protocol = TCP``), so a firewall that drops ping does not hide the latency.
Targets are measured concurrently (ping probes are tiny, so they do not disturb
each other), but the module as a whole runs without other network tests.
"""

from __future__ import annotations

import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, Optional

from app.constants import LATENCY_TARGETS
from app.core.icmp import latency_stats, run_ping
from app.diag.adapter import check_from_result
from app.diag.probes import resolve, tcp_attempt
from app.diag.results import Severity, TechnicalStatus, TestResult
from app.diag.testconfig import DEFAULT_CONFIG, NetworkTestConfig
from app.logger import get_logger
from app.models import ModuleReport

log = get_logger(__name__)
_S = TechnicalStatus

ProgressCallback = Optional[Callable[[str], None]]

HIGH_LATENCY_MS = 200.0
TCP_SAMPLE_PORT = 443
TCP_SAMPLE_GAP_S = 0.1


class LatencyTester:
    def __init__(self, targets: Optional[dict[str, str]] = None, progress_cb: ProgressCallback = None,
                 config: NetworkTestConfig = DEFAULT_CONFIG, cancel: Optional[threading.Event] = None) -> None:
        self.targets = targets or dict(LATENCY_TARGETS)
        self.progress_cb = progress_cb
        self.config = config
        self.cancel = cancel or threading.Event()

    def _report(self, message: str) -> None:
        if self.progress_cb:
            self.progress_cb(message)
        log.info(message)

    # -- measurements -----------------------------------------------------
    def _tcp_samples(self, host: str) -> tuple[list[float], str | None]:
        res = resolve(host)
        if not res.ok:
            return [], res.error.error_code if res.error else "DNS_FAILED"
        rtts: list[float] = []
        for _ in range(self.config.latency_probes):
            if self.cancel.is_set():
                break
            err, elapsed, _local = tcp_attempt(res.ip or "", TCP_SAMPLE_PORT, self.config.connect_timeout)
            # A refusal is still an answer from the host, so it is a valid RTT sample.
            if err is None or err.error_code == "CONNECTION_REFUSED":
                rtts.append(elapsed)
            time.sleep(TCP_SAMPLE_GAP_S)
        return rtts, None

    def measure(self, name: str, host: str) -> TestResult:
        n = self.config.latency_probes
        self._report(f"Measuring latency to {name} ({host}) ...")
        started = time.perf_counter()
        ping = run_ping(host, n, self.config.ping_timeout, interval_s=0.2)
        protocol, rtts = "ICMP", ping.rtts
        fallback_note = None
        if not rtts and not self.cancel.is_set() and ping.error_hint != "NETWORK_UNREACHABLE":
            tcp_rtts, why = self._tcp_samples(host)
            if tcp_rtts:
                protocol, rtts = f"TCP/{TCP_SAMPLE_PORT}", tcp_rtts
                fallback_note = "ICMP echo got no reply, so TCP handshake times were measured instead."

        stats = latency_stats(rtts, n)
        res = TestResult(f"latency.{host}", "latency", target=host, protocol=protocol,
                         metrics={**stats, "measured_with": protocol}, metadata={"name": name, "rtts_ms": rtts},
                         duration_ms=(time.perf_counter() - started) * 1000.0)
        if fallback_note:
            res.warnings.append(fallback_note)
        loss = float(stats["packet_loss_percent"] or 0.0)
        avg = stats["average_ms"]
        if not rtts:
            res.status, res.severity = _S.TIMEOUT, Severity.WARNING
            res.error_code = ping.error_hint or "TIMEOUT"
            res.interpretation = "NO_REPLY_TO_ANY_PROBE"
            res.summary = f"{name}: no reply to {n} ICMP probes and no TCP answer; latency could not be measured."
            return res
        degraded = loss > 0 or (avg is not None and avg > HIGH_LATENCY_MS)
        res.status = _S.PARTIAL if degraded else _S.SUCCESS
        res.severity = Severity.WARNING if degraded else Severity.OK
        res.summary = (f"{name} ({protocol}): {stats['packets_received']}/{stats['packets_sent']} replies, "
                       f"avg {avg} ms, min {stats['min_ms']}, max {stats['max_ms']}, "
                       f"jitter {stats['jitter_ms']} ms, loss {loss:.0f}%.")
        res.add_evidence(f"{stats['packets_received']} of {stats['packets_sent']} probes answered over {protocol}")
        return res

    def run_all(self) -> ModuleReport:
        report = ModuleReport(module_name="Latency Test")
        items = list(self.targets.items())
        with ThreadPoolExecutor(max_workers=max(1, min(len(items), 4)), thread_name_prefix="icpa-lat") as pool:
            futures = [pool.submit(self._safe, n, h) for n, h in items]
            results = [f.result() for f in futures]
        for (name, host), res in zip(items, results):
            m = res.metrics
            details = {"target": host, "sent": m.get("packets_sent"), "received": m.get("packets_received"),
                       "loss_percent": m.get("packet_loss_percent"), "rtts_ms": res.metadata.get("rtts_ms", []),
                       "average_ms": m.get("average_ms"), "jitter_ms": m.get("jitter_ms"),
                       "min_ms": m.get("min_ms"), "median_ms": m.get("median_ms"), "max_ms": m.get("max_ms"),
                       "measured_with": res.protocol}
            report.add(check_from_result(f"Latency to {name}", res, details=details))
        report.finish()
        return report

    def _safe(self, name: str, host: str) -> TestResult:
        try:
            return self.measure(name, host)
        except Exception as exc:  # noqa: BLE001 - one target must not break the module
            log.exception("latency measurement for %s crashed", host)
            return TestResult(f"latency.{host}", "latency", status=_S.ERROR, target=host,
                              error_type=type(exc).__name__, error_message=str(exc)[:200],
                              summary=f"{name}: latency could not be measured (internal error).")
