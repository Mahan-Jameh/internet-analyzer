"""
home_tab.py
===========
The landing tab: shows a snapshot of the current network environment
(public IP, ISP, geo, adapter, gateway, DNS servers, IPv4/IPv6 status).
Collected on a background thread so the UI never blocks while the geo
IP lookup (a network request) is in flight.
"""

from __future__ import annotations

from PySide6.QtCore import QThread, Signal
from PySide6.QtWidgets import QHBoxLayout, QLabel, QPushButton, QVBoxLayout, QWidget

from app.core.network_info import NetworkInfoCollector
from app.i18n import tr
from app.gui.results_widgets import NetworkInfoGrid
from app.logger import get_logger
from app.models import NetworkInfo

log = get_logger(__name__)


class _NetworkInfoThread(QThread):
    finished_with_result = Signal(object)

    def run(self) -> None:
        try:
            info = NetworkInfoCollector().collect()
        except Exception:  # noqa: BLE001 - must never crash the UI
            log.exception("Network info collection failed")
            info = NetworkInfo()
        self.finished_with_result.emit(info)


class HomeTab(QWidget):
    network_info_updated = Signal(object)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._thread: _NetworkInfoThread | None = None
        self.latest_info: NetworkInfo | None = None

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        header = QHBoxLayout()
        title = QLabel(tr("Network Overview"))
        title.setObjectName("sectionTitle")
        header.addWidget(title)
        header.addStretch(1)

        self.refresh_btn = QPushButton(tr("Refresh"))
        self.refresh_btn.clicked.connect(self.refresh)
        header.addWidget(self.refresh_btn)
        layout.addLayout(header)

        subtitle = QLabel(tr(
            "This is a snapshot of your current network environment. "
            "Run the Diagnostics tab for a full set of tests."
        ))
        subtitle.setObjectName("mutedLabel")
        subtitle.setWordWrap(True)
        layout.addWidget(subtitle)

        self.grid = NetworkInfoGrid()
        layout.addWidget(self.grid)
        layout.addStretch(1)

    def refresh(self) -> None:
        if self._thread and self._thread.isRunning():
            return
        self.refresh_btn.setEnabled(False)
        self.refresh_btn.setText(tr("Refreshing..."))
        self._thread = _NetworkInfoThread()
        self._thread.finished_with_result.connect(self._on_result)
        self._thread.start()

    def shutdown(self) -> None:
        """Wait for the background lookup before the window closes."""
        if self._thread is not None and self._thread.isRunning():
            self._thread.wait(8000)

    def _on_result(self, info: NetworkInfo) -> None:
        self.show_info(info)
        self.refresh_btn.setEnabled(True)
        self.refresh_btn.setText(tr("Refresh"))
        self.network_info_updated.emit(info)

    def show_info(self, info: NetworkInfo) -> None:
        """Display already collected network information (also used after a language switch)."""
        self.latest_info = info
        self.grid.update_info(info)
