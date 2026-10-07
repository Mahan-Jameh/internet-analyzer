"""
main_window.py
==============
The top level QMainWindow: hosts the Home / Diagnostics / Advanced /
History / Logs tabs, wires their signals together, and holds the persisted
:class:`ConfigManager` used to remember window size and preferences.

The interface language (Persian, right-to-left, or English) can be switched
from the Language menu. Switching rebuilds the tabs, and the latest report
and network information are put back so nothing the user was looking at is lost.
"""

from __future__ import annotations

from PySide6.QtGui import QActionGroup, QCloseEvent
from PySide6.QtWidgets import (
    QApplication,
    QMainWindow,
    QMessageBox,
    QTabWidget,
)

from app import i18n
from app.config import ConfigManager
from app.constants import APP_NAME, APP_VERSION
from app.export.history import save_to_history
from app.gui.advanced_tab import AdvancedTab
from app.gui.export_dialog import ExportDialog
from app.gui.history_tab import HistoryTab
from app.gui.home_tab import HomeTab
from app.gui.logs_tab import LogsTab
from app.gui.styles import DARK_STYLESHEET
from app.gui.tests_tab import DiagnosticsTab
from app.i18n import tr
from app.logger import get_logger
from app.models import FullReport, NetworkInfo

log = get_logger(__name__)


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.config_manager = ConfigManager()
        settings = self.config_manager.settings

        i18n.set_language(settings.language)
        app = QApplication.instance()
        if app is not None:
            i18n.apply_to_application(app)

        self.resize(settings.window_width, settings.window_height)
        self.setStyleSheet(DARK_STYLESHEET)

        self.tabs: QTabWidget | None = None
        self._build_ui()

        # Kick off an initial network info refresh on startup.
        self.home_tab.refresh()

    # ------------------------------------------------------------------ #
    # building the interface (also used again after a language switch)
    # ------------------------------------------------------------------ #
    def _build_ui(self) -> None:
        self.setWindowTitle(f"{tr(APP_NAME)}  v{APP_VERSION}")

        self.tabs = QTabWidget()
        self.home_tab = HomeTab()
        self.diagnostics_tab = DiagnosticsTab()
        self.advanced_tab = AdvancedTab()
        self.history_tab = HistoryTab()
        self.logs_tab = LogsTab()

        self.tabs.addTab(self.home_tab, tr("Home"))
        self.tabs.addTab(self.diagnostics_tab, tr("Diagnostics"))
        self.tabs.addTab(self.advanced_tab, tr("Advanced"))
        self.tabs.addTab(self.history_tab, tr("History"))
        self.tabs.addTab(self.logs_tab, tr("Logs"))
        self.setCentralWidget(self.tabs)

        self._wire_signals()
        self._build_menu()

    def _wire_signals(self) -> None:
        self.diagnostics_tab.network_info_ready.connect(self.home_tab.grid.update_info)
        self.diagnostics_tab.report_ready.connect(self._on_report_ready)
        self.diagnostics_tab.export_btn.clicked.connect(self._open_export_dialog)
        self.advanced_tab.run_requested.connect(self._run_advanced)

    def _build_menu(self) -> None:
        menu_bar = self.menuBar()
        menu_bar.clear()

        file_menu = menu_bar.addMenu(tr("&File"))
        export_action = file_menu.addAction(tr("Export Current Report..."))
        export_action.triggered.connect(self._open_export_dialog)
        file_menu.addSeparator()
        exit_action = file_menu.addAction(tr("Exit"))
        exit_action.triggered.connect(self.close)

        language_menu = menu_bar.addMenu(tr("&Language"))
        group = QActionGroup(self)
        group.setExclusive(True)
        for code, label in i18n.SUPPORTED_LANGUAGES.items():
            action = language_menu.addAction(label)
            action.setCheckable(True)
            action.setChecked(code == i18n.get_language())
            action.triggered.connect(lambda _checked=False, c=code: self.switch_language(c))
            group.addAction(action)

        help_menu = menu_bar.addMenu(tr("&Help"))
        about_action = help_menu.addAction(tr("About"))
        about_action.triggered.connect(self._show_about)

    # ------------------------------------------------------------------ #
    # language switching
    # ------------------------------------------------------------------ #
    def switch_language(self, code: str) -> None:
        if code == i18n.get_language():
            return
        if self.diagnostics_tab.is_busy():
            QMessageBox.information(
                self, tr("Language"),
                tr("Please stop or wait for the running diagnostic to finish before changing the language."),
            )
            self._build_menu()      # put the radio selection back
            return

        # Remember what is on screen so it can be restored in the new language.
        report = self.diagnostics_tab.current_report
        info: NetworkInfo | None = self.home_tab.latest_info
        current_index = self.tabs.currentIndex() if self.tabs is not None else 0

        self.diagnostics_tab.shutdown()
        self.home_tab.shutdown()

        i18n.set_language(code)
        self.config_manager.settings.language = code
        self.config_manager.save()
        app = QApplication.instance()
        if app is not None:
            i18n.apply_to_application(app)

        self._build_ui()      # setCentralWidget() disposes of the old tab widget

        if info is not None:
            self.home_tab.show_info(info)
        else:
            self.home_tab.refresh()
        if report is not None:
            self.diagnostics_tab.show_report(report)
        self.tabs.setCurrentIndex(current_index)
        log.info("Interface language changed to %s", code)

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
                self, tr("No Report Yet"), tr("Run a diagnostic first before exporting a report.")
            )
            return
        dialog = ExportDialog(report, parent=self)
        dialog.exec()

    def _show_about(self) -> None:
        QMessageBox.information(
            self,
            tr("About"),
            f"{tr(APP_NAME)}\n{tr('Version')} {APP_VERSION}\n\n"
            + tr(
                "A diagnostic tool for ordinary users to understand Internet "
                "connectivity, protocol support, and possible network restrictions "
                "on their own machine.\n\n"
                "This tool only diagnoses - it never attempts to bypass any restriction."
            ),
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
