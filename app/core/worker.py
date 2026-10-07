"""
worker.py
=========
A QThread-based worker that runs the selected diagnostic modules off the
GUI thread, emitting progress and per-module signals so the UI can update
live and never freezes during long-running network tests.

Guarantees:
  * "network_info" always runs (the analyzer needs it) and starts first.
  * modules run through the dependency graph in ``app.core.runner``: independent
    modules in parallel, name-based tests only after DNS did not provably fail.
  * one failing module never stops the others - it becomes an UNKNOWN result.
  * the run can be cancelled at any time (``requestInterruption`` sets a shared
    cancel event that every module and probe checks).
  * every run is summarised in the log: timestamp, duration, errors, network info.
"""

from __future__ import annotations

import threading
import time
from datetime import datetime
from typing import Optional

from PySide6.QtCore import QThread, Signal

from app.core.analyzer import ResultAnalyzer
from app.core.runner import (  # noqa: F401 - re-exported for the GUI and the tests
    ALL_MODULES,
    DEFAULT_MODULES,
    MODULE_DEPENDENCIES,
    MODULE_DISPLAY_NAMES,
    OPT_IN_MODULES,
    DiagnosticRunner,
    RunParams,
    normalize_modules,
)
from app.diag.testconfig import DEFAULT_CONFIG, NetworkTestConfig
from app.logger import get_logger
from app.models import FullReport, ModuleReport, NetworkInfo
from app.utils.helpers import validate_target_host

log = get_logger(__name__)


class DiagnosticWorker(QThread):
    """Runs the requested test modules on a background thread (dependency-aware, bounded concurrency)."""

    progress_message = Signal(str)
    module_started = Signal(str)
    module_finished = Signal(object)      # emits a ModuleReport
    network_info_ready = Signal(object)   # emits a NetworkInfo
    run_finished = Signal(object)         # emits the final FullReport
    run_failed = Signal(str)

    def __init__(
        self,
        modules_to_run: Optional[list[str]] = None,
        target_host: Optional[str] = None,
        tcp_ports: Optional[list[int]] = None,
        udp_ports: Optional[list[int]] = None,
        test_sites: Optional[list[str]] = None,
        profile_name: Optional[str] = None,
        parent=None,
        config: NetworkTestConfig = DEFAULT_CONFIG,
    ) -> None:
        super().__init__(parent)
        self.modules_to_run = normalize_modules(modules_to_run)
        self.target_host = validate_target_host(target_host)
        if target_host and self.target_host is None:
            log.warning("Ignoring invalid target host: %r", target_host)
        self.tcp_ports = tcp_ports
        self.udp_ports = udp_ports
        self.test_sites = test_sites
        self.profile_name = profile_name
        self.config = config
        self.cancel_event = threading.Event()
        self._network_info: NetworkInfo = NetworkInfo()
        self._module_reports: list[ModuleReport] = []

    def requestInterruption(self) -> None:  # noqa: N802 - Qt API name
        """Cancel cooperatively: probes check the shared event and stop retrying/starting."""
        self.cancel_event.set()
        super().requestInterruption()

    # ------------------------------------------------------------------ #
    def run(self) -> None:
        started_wall = datetime.now()
        started = time.perf_counter()
        try:
            runner = DiagnosticRunner(
                self.modules_to_run,
                RunParams(self.target_host, self.tcp_ports, self.udp_ports, self.test_sites),
                self.config, self.cancel_event,
                progress=self.progress_message.emit,
                on_module_started=self.module_started.emit,
                on_module_finished=self.module_finished.emit,
                on_network_info=self.network_info_ready.emit,
            )
            output = runner.run()
            self._network_info, self._module_reports = output.network_info, output.reports
            cancelled = output.cancelled or self.isInterruptionRequested()

            duration = time.perf_counter() - started
            interpretations, summary = ResultAnalyzer().analyze_full(self._network_info, self._module_reports)
            full_report = FullReport(
                network_info=self._network_info,
                modules=self._module_reports,
                interpretations=interpretations,
                generated_at=started_wall,
                profile_name=self.profile_name,
                duration_seconds=round(duration, 2),
                cancelled=cancelled,
                target_host=self.target_host,
                summary=summary,
            )
            self._log_run_summary(full_report, output.errors)
            self.progress_message.emit("Run cancelled." if cancelled else "All tests completed.")
            self.run_finished.emit(full_report)

        except Exception as exc:  # noqa: BLE001 - the run must never crash the app
            log.exception("Diagnostic run failed")
            self.run_failed.emit(str(exc))

    # ------------------------------------------------------------------ #
    def _log_run_summary(self, report: FullReport, errors: list[str]) -> None:
        info = report.network_info
        log.info(
            "RUN SUMMARY | started=%s | duration=%.1fs | cancelled=%s | modules=%d | errors=%d",
            report.generated_at.strftime("%Y-%m-%d %H:%M:%S"), report.duration_seconds or 0.0,
            report.cancelled, len(report.modules), len(errors),
        )
        log.info(
            "RUN NETWORK | public_ip=%s | isp=%s | country=%s | ipv4=%s | ipv6=%s | public_ip_state=%s | dns=%s | gateway=%s",
            info.public_ip, info.isp, info.country, info.ipv4_state, info.ipv6_state, info.public_ip_state,
            ",".join(info.dns_servers) or "-", info.gateway,
        )
        for message in errors:
            log.error("RUN ERROR | %s", message)
