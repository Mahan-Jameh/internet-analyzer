"""
main_window.py
==============
The top level QMainWindow: hosts the Home / Diagnostics / Advanced /
Logs tabs, wires their signals together, and holds the persisted
:class:`ConfigManager` used to remember window size and preferences.
"""

from __future__ import annotations

from PySide6.QtGui import QCloseEvent
from PySide6.QtWidgets import (
    QMainWindow,
    QMessageBox,
    QTabWidget,
)

from app.config import ConfigManager
from app.constants import APP_NAME, APP_VERSION
from app.gui.advanced_tab import AdvancedTab
from app.gui.export_dialog import ExportDialog
from app.export.history import save_to_history
from app.gui.history_tab import HistoryTab
from app.gui.home_tab import HomeTab
from app.gui.logs_tab import LogsTab
from app.gui.styles import DARK_STYLESHEET
from app.gui.tests_tab import DiagnosticsTab
from app.logger import get_logger
from app.models import FullReport

log = get_logger(__name__)


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.config_manager = ConfigManager()
        settings = self.config_manager.settings

        self.setWindowTitle(f"{APP_NAME}  v{APP_VERSION}")
        self.resize(settings.window_width, settings.window_height)
        self.setStyleSheet(DARK_STYLESHEET)

        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)

        self.home_tab = HomeTab()
        self.diagnostics_tab = DiagnosticsTab()
        self.advanced_tab = AdvancedTab()
        self.history_tab = HistoryTab()
        self.logs_tab = LogsTab()

        self.tabs.addTab(self.home_tab, "Home")
        self.tabs.addTab(self.diagnostics_tab, "Diagnostics")
        self.tabs.addTab(self.advanced_tab, "Advanced")
        self.tabs.addTab(self.history_tab, "History")
        self.tabs.addTab(self.logs_tab, "Logs")

        self._wire_signals()
        self._build_menu()

        # Kick off an initial network info refresh on startup.
        self.home_tab.refresh()

    # ------------------------------------------------------------------ #
    def _wire_signals(self) -> None:
        self.diagnostics_tab.network_info_ready.connect(self.home_tab.grid.update_info)
        self.diagnostics_tab.report_ready.connect(self._on_report_ready)
        self.diagnostics_tab.export_btn.clicked.connect(self._open_export_dialog)
        self.advanced_tab.run_requested.connect(self._run_advanced)

    def _build_menu(self) -> None:
        menu_bar = self.menuBar()

        file_menu = menu_bar.addMenu("&File")
        export_action = file_menu.addAction("Export Current Report...")
        export_action.triggered.connect(self._open_export_dialog)
        file_menu.addSeparator()
        exit_action = file_menu.addAction("Exit")
        exit_action.triggered.connect(self.close)

        help_menu = menu_bar.addMenu("&Help")
        about_action = help_menu.addAction("About")
        about_action.triggered.connect(self._show_about)

    # ------------------------------------------------------------------ #
    def _run_advanced(self, target_host: str, tcp_ports: list[int], udp_ports: list[int],
                      test_sites: list[str]) -> None:
        self.tabs.setCurrentWidget(self.diagnostics_tab)
        self.diagnostics_tab.start_run(
            target_host=target_host or None,
            tcp_ports=tcp_ports or None,
            udp_ports=udp_ports or None,
            test_sites=test_sites or None,
        )

    def _on_report_ready(self, report: FullReport) -> None:
        log.info("Diagnostic report ready with %d module(s).", len(report.modules))
        path = save_to_history(report)
        if path is not None:
            log.info("Report saved to history: %s", path)
            self.history_tab.refresh()

    def _open_export_dialog(self) -> None:
        report = self.diagnostics_tab.current_report
        if report is None:
            QMessageBox.information(
                self, "No Report Yet", "Run a diagnostic first before exporting a report."
            )
            return
        dialog = ExportDialog(report, parent=self)
        dialog.exec()

    def _show_about(self) -> None:
        QMessageBox.information(
            self,
            "About",
            f"{APP_NAME}\nVersion {APP_VERSION}\n\n"
            "A diagnostic tool for ordinary users to understand Internet "
            "connectivity, protocol support, and possible network restrictions "
            "on their own machine.\n\n"
            "This tool only diagnoses - it never attempts to bypass any restriction.",
        )

    # ------------------------------------------------------------------ #
    def closeEvent(self, event: QCloseEvent) -> None:  # noqa: N802 - Qt override
        # Stop background threads first, otherwise Qt aborts with
        # "QThread: Destroyed while thread is still running".
        self.diagnostics_tab.shutdown()
        self.home_tab.shutdown()
        self.config_manager.settings.window_width = self.width()
        self.config_manager.settings.window_height = self.height()
        self.config_manager.save()
        super().closeEvent(event)
