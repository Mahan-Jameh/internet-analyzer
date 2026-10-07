"""
tests_tab.py
============
The main "Diagnostics" tab.

  * choose which test modules to run (the whole run, or just a few)
  * run once or repeat N times with a pause between runs
  * live progress bar and status line, with a Stop button
  * one card per module: gray while waiting / not tested, colored when done
  * an "Analysis Summary" card with the probabilistic interpretations
"""

from __future__ import annotations

from typing import Optional

from PySide6.QtCore import QTimer, Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QFrame,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from app.constants import REPEAT_MAX_COUNT, REPEAT_MAX_INTERVAL_SECONDS
from app.core.worker import (
    ALL_MODULES,
    DEFAULT_MODULES,
    MODULE_DISPLAY_NAMES,
    OPT_IN_MODULES,
    DiagnosticWorker,
)
from app.gui.results_widgets import ModuleResultCard, PlaceholderCard, StatusBadge
from app.logger import get_logger
from app.models import FullReport, Interpretation, ModuleReport, NetworkInfo

log = get_logger(__name__)

_SELECTABLE_MODULES = [m for m in ALL_MODULES if m != "network_info"]


class InterpretationRow(QFrame):
    def __init__(self, interp: Interpretation, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setStyleSheet("background-color:#2a2c38; border-radius:8px;")
        layout = QHBoxLayout(self)
        layout.setContentsMargins(12, 8, 12, 8)

        badge = StatusBadge(interp.severity.value)
        badge.setFixedWidth(100)
        layout.addWidget(badge)

        label = QLabel(interp.text)
        label.setWordWrap(True)
        layout.addWidget(label, stretch=1)


class DiagnosticsTab(QWidget):
    report_ready = Signal(object)          # FullReport
    network_info_ready = Signal(object)    # NetworkInfo

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._worker: Optional[DiagnosticWorker] = None
        self._current_report: Optional[FullReport] = None
        self._cards: dict[str, QWidget] = {}
        self._last_params: dict = {}
        self._done_steps = 0
        self._repeats_left = 0
        self._run_index = 1
        self._run_total = 1
        self._cancel_requested = False
        self._waiting_for_next_run = False
        self._status_prefix = ""

        self._repeat_timer = QTimer(self)
        self._repeat_timer.setSingleShot(True)
        self._repeat_timer.timeout.connect(self._launch)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(12)

        # --- header ---------------------------------------------------------
        header = QHBoxLayout()
        title = QLabel("Diagnostics")
        title.setObjectName("sectionTitle")
        header.addWidget(title)
        header.addStretch(1)

        self.run_btn = QPushButton("Run Diagnostic")
        self.run_btn.clicked.connect(lambda: self.start_run())
        header.addWidget(self.run_btn)

        self.stop_btn = QPushButton("Stop")
        self.stop_btn.setObjectName("secondaryButton")
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self._on_stop)
        header.addWidget(self.stop_btn)

        self.export_btn = QPushButton("Export Report...")
        self.export_btn.setObjectName("secondaryButton")
        self.export_btn.setEnabled(False)
        header.addWidget(self.export_btn)
        layout.addLayout(header)

        # --- options --------------------------------------------------------
        self.options_box = QGroupBox("Tests to run")
        options_layout = QVBoxLayout(self.options_box)

        grid = QGridLayout()
        self.module_checks: dict[str, QCheckBox] = {}
        for i, key in enumerate(_SELECTABLE_MODULES):
            checkbox = QCheckBox(MODULE_DISPLAY_NAMES[key])
            checkbox.setChecked(key in DEFAULT_MODULES)
            if key in OPT_IN_MODULES:
                checkbox.setText(MODULE_DISPLAY_NAMES[key] + "  (optional)")
                checkbox.setToolTip(
                    "May briefly interrupt your connection (a filter can drop your packets for "
                    "about a minute after seeing unusual traffic). You will be asked to confirm."
                )
            self.module_checks[key] = checkbox
            grid.addWidget(checkbox, i // 3, i % 3)
        options_layout.addLayout(grid)

        controls = QHBoxLayout()
        select_all = QPushButton("Select all")
        select_all.setObjectName("secondaryButton")
        select_all.clicked.connect(lambda: self._set_all_checks(True))
        controls.addWidget(select_all)
        defaults = QPushButton("Default selection")
        defaults.setObjectName("secondaryButton")
        defaults.clicked.connect(self._reset_default_checks)
        controls.addWidget(defaults)
        controls.addStretch(1)

        controls.addWidget(QLabel("Repeat"))
        self.repeat_spin = QSpinBox()
        self.repeat_spin.setRange(1, REPEAT_MAX_COUNT)
        self.repeat_spin.setSuffix(" time(s)")
        controls.addWidget(self.repeat_spin)
        controls.addWidget(QLabel("every"))
        self.interval_spin = QSpinBox()
        self.interval_spin.setRange(0, REPEAT_MAX_INTERVAL_SECONDS)
        self.interval_spin.setValue(30)
        self.interval_spin.setSuffix(" s")
        controls.addWidget(self.interval_spin)
        options_layout.addLayout(controls)
        layout.addWidget(self.options_box)

        # --- status / progress ----------------------------------------------
        self.status_label = QLabel("Ready. Click \"Run Diagnostic\" to begin.")
        self.status_label.setObjectName("mutedLabel")
        layout.addWidget(self.status_label)

        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 1)
        self.progress_bar.setValue(0)
        layout.addWidget(self.progress_bar)

        # --- results -----------------------------------------------------------
        self.scroll_area = QScrollArea()
        self.scroll_area.setWidgetResizable(True)
        self.results_container = QWidget()
        self.results_layout = QVBoxLayout(self.results_container)
        self.results_layout.setSpacing(10)
        self.results_layout.addStretch(1)
        self.scroll_area.setWidget(self.results_container)
        layout.addWidget(self.scroll_area, stretch=1)

    # ------------------------------------------------------------------ #
    # selection helpers
    # ------------------------------------------------------------------ #
    def selected_modules(self) -> list[str]:
        return [k for k in _SELECTABLE_MODULES if self.module_checks[k].isChecked()]

    def _set_all_checks(self, checked: bool) -> None:
        for checkbox in self.module_checks.values():
            checkbox.setChecked(checked)

    def _reset_default_checks(self) -> None:
        for key, checkbox in self.module_checks.items():
            checkbox.setChecked(key in DEFAULT_MODULES)

    # ------------------------------------------------------------------ #
    # starting / stopping
    # ------------------------------------------------------------------ #
    def start_run(
        self,
        modules: Optional[list[str]] = None,
        target_host: Optional[str] = None,
        tcp_ports: Optional[list[int]] = None,
        udp_ports: Optional[list[int]] = None,
        test_sites: Optional[list[str]] = None,
    ) -> None:
        """Start a user-initiated run (a series, if "Repeat" is more than 1)."""
        if self.is_busy():
            return

        chosen = modules or self.selected_modules()
        if not chosen:
            self.status_label.setText("Select at least one test to run.")
            return

        if any(m in OPT_IN_MODULES for m in chosen):
            answer = QMessageBox.warning(
                self,
                "Optional test may interrupt your connection",
                "The Protocol Whitelist Probe sends unusual traffic on purpose. A network "
                "filter that reacts to it may drop your packets for about a minute, so "
                "websites may stop loading briefly.\n\nRun it anyway?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if answer != QMessageBox.StandardButton.Yes:
                return

        self._last_params = {
            "modules_to_run": chosen,
            "target_host": target_host or None,
            "tcp_ports": tcp_ports,
            "udp_ports": udp_ports,
            "test_sites": test_sites,
        }
        self._run_total = self.repeat_spin.value()
        self._run_index = 1
        self._repeats_left = self._run_total - 1
        self._cancel_requested = False
        self._launch()

    def _launch(self) -> None:
        """Start one run with the stored parameters."""
        self._waiting_for_next_run = False
        self._clear_results()
        self._done_steps = 0

        worker = DiagnosticWorker(**self._last_params)
        self._worker = worker

        self._cards.clear()
        for key in _SELECTABLE_MODULES:
            name = MODULE_DISPLAY_NAMES[key]
            label = "WAITING" if key in worker.modules_to_run else "NOT TESTED"
            card = PlaceholderCard(name, label)
            self._cards[name] = card
            self.results_layout.insertWidget(self.results_layout.count() - 1, card)

        self.progress_bar.setRange(0, len(worker.modules_to_run))
        self.progress_bar.setValue(0)
        prefix = f"Run {self._run_index} of {self._run_total}: " if self._run_total > 1 else ""
        self._status_prefix = prefix
        self.status_label.setText(prefix + "Starting diagnostics...")
        self._set_running_ui(True)

        worker.progress_message.connect(self._on_progress)
        worker.module_started.connect(self._on_module_started)
        worker.module_finished.connect(self._on_module_finished)
        worker.network_info_ready.connect(self._on_network_info)
        worker.run_finished.connect(self._on_run_finished)
        worker.run_failed.connect(self._on_run_failed)
        worker.start()

    def _on_stop(self) -> None:
        self._cancel_requested = True
        self._repeats_left = 0
        self._repeat_timer.stop()
        if self._worker is not None and self._worker.isRunning():
            self._worker.requestInterruption()
            self.status_label.setText("Stopping after the current test finishes...")
            self.stop_btn.setEnabled(False)
        elif self._waiting_for_next_run:
            self._waiting_for_next_run = False
            self.status_label.setText("Repeat series stopped.")
            self._set_running_ui(False)

    def is_busy(self) -> bool:
        running = self._worker is not None and self._worker.isRunning()
        return running or self._waiting_for_next_run

    def shutdown(self) -> None:
        """Called when the window closes: stop timers and wait for the worker thread."""
        self._repeats_left = 0
        self._repeat_timer.stop()
        if self._worker is not None and self._worker.isRunning():
            self._worker.requestInterruption()
            self._worker.wait(8000)

    def _set_running_ui(self, running: bool) -> None:
        self.run_btn.setEnabled(not running)
        self.stop_btn.setEnabled(running)
        self.options_box.setEnabled(not running)
        if running:
            self.export_btn.setEnabled(False)

    # ------------------------------------------------------------------ #
    # result cards
    # ------------------------------------------------------------------ #
    def _clear_results(self) -> None:
        while self.results_layout.count() > 1:
            item = self.results_layout.takeAt(0)
            widget = item.widget()
            if widget:
                widget.deleteLater()

    def _replace_card(self, module_name: str, new_card: QWidget) -> None:
        old = self._cards.get(module_name)
        if old is None:
            self.results_layout.insertWidget(self.results_layout.count() - 1, new_card)
        else:
            index = self.results_layout.indexOf(old)
            self.results_layout.removeWidget(old)
            old.deleteLater()
            self.results_layout.insertWidget(index if index >= 0 else self.results_layout.count() - 1,
                                             new_card)
        self._cards[module_name] = new_card

    # ------------------------------------------------------------------ #
    # worker signals
    # ------------------------------------------------------------------ #
    def _on_progress(self, message: str) -> None:
        self.status_label.setText(self._status_prefix + message)

    def _on_module_started(self, display_name: str) -> None:
        card = self._cards.get(display_name)
        if isinstance(card, PlaceholderCard):
            card.set_label("RUNNING")

    def _on_module_finished(self, report: ModuleReport) -> None:
        self._replace_card(report.module_name, ModuleResultCard(report))
        self._done_steps += 1
        self.progress_bar.setValue(self._done_steps)

    def _on_network_info(self, info: NetworkInfo) -> None:
        self._done_steps += 1
        self.progress_bar.setValue(self._done_steps)
        self.network_info_ready.emit(info)

    def _on_run_finished(self, report: FullReport) -> None:
        self._current_report = report

        # Anything that never ran (cancelled run) is shown as not tested.
        for card in self._cards.values():
            if isinstance(card, PlaceholderCard):
                card.set_label("NOT TESTED")

        self._insert_summary(report)
        self.export_btn.setEnabled(True)
        self.report_ready.emit(report)

        if not self._cancel_requested and self._repeats_left > 0:
            self._repeats_left -= 1
            self._run_index += 1
            delay = self.interval_spin.value()
            self._waiting_for_next_run = True
            self.stop_btn.setEnabled(True)
            self.run_btn.setEnabled(False)
            self.status_label.setText(
                f"Run {self._run_index - 1} of {self._run_total} finished. "
                f"Next run in {delay} s (press Stop to cancel)."
            )
            self._repeat_timer.start(delay * 1000)
            return

        text = "Run cancelled." if report.cancelled else "All tests completed."
        if report.duration_seconds is not None:
            text += f" Took {report.duration_seconds:.0f} s."
        self.status_label.setText(text)
        self.progress_bar.setValue(self.progress_bar.maximum())
        self._set_running_ui(False)
        self.export_btn.setEnabled(True)

    def _on_run_failed(self, message: str) -> None:
        self._repeats_left = 0
        self.status_label.setText(f"The run could not be completed: {message}")
        self._set_running_ui(False)

    def _insert_summary(self, report: FullReport) -> None:
        summary = QFrame()
        summary.setStyleSheet("background-color:#25262f; border-radius:10px;")
        summary_layout = QVBoxLayout(summary)
        title = QLabel("Analysis Summary")
        title.setObjectName("sectionTitle")
        summary_layout.addWidget(title)
        note = QLabel(
            "These are probabilistic interpretations based on the observed results - "
            "not definitive claims about censorship or network policy."
        )
        note.setObjectName("mutedLabel")
        note.setWordWrap(True)
        summary_layout.addWidget(note)
        for interp in report.interpretations:
            summary_layout.addWidget(InterpretationRow(interp))
        self.results_layout.insertWidget(0, summary)

    @property
    def current_report(self) -> Optional[FullReport]:
        return self._current_report
