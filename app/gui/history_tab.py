"""
history_tab.py
==============
Every finished run is saved automatically. This tab lists those saved
runs and compares any two of them: which checks got better, which got
worse, and whether the network environment (IP, ISP, DNS, IPv6 ...) changed.
Useful for "it worked yesterday" questions, or for before/after a change
such as turning a VPN off.
"""

from __future__ import annotations

from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QComboBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from app.core.compare import DEGRADED, IMPROVED, ComparisonResult, compare_reports
from app.export.history import HistoryEntry, list_history, load_report
from app.gui.styles import COLOR_FAILED, COLOR_OK, COLOR_WARNING, STATUS_COLOR_MAP
from app.logger import get_logger

log = get_logger(__name__)

_CHANGE_COLORS = {IMPROVED: COLOR_OK, DEGRADED: COLOR_FAILED}


class HistoryTab(QWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._entries: list[HistoryEntry] = []

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(12)

        title = QLabel("History & Comparison")
        title.setObjectName("sectionTitle")
        layout.addWidget(title)

        info = QLabel(
            "Every completed run is saved automatically. Pick two runs to see what changed "
            "between them."
        )
        info.setObjectName("mutedLabel")
        info.setWordWrap(True)
        layout.addWidget(info)

        pick_row = QHBoxLayout()
        pick_row.addWidget(QLabel("Earlier run:"))
        self.older_combo = QComboBox()
        self.older_combo.setMinimumWidth(240)
        pick_row.addWidget(self.older_combo, stretch=1)
        pick_row.addWidget(QLabel("Later run:"))
        self.newer_combo = QComboBox()
        self.newer_combo.setMinimumWidth(240)
        pick_row.addWidget(self.newer_combo, stretch=1)
        layout.addLayout(pick_row)

        button_row = QHBoxLayout()
        self.compare_btn = QPushButton("Compare Selected")
        self.compare_btn.clicked.connect(self.compare_selected)
        button_row.addWidget(self.compare_btn)
        latest_btn = QPushButton("Compare Latest Two")
        latest_btn.setObjectName("secondaryButton")
        latest_btn.clicked.connect(self.compare_latest_two)
        button_row.addWidget(latest_btn)
        refresh_btn = QPushButton("Refresh List")
        refresh_btn.setObjectName("secondaryButton")
        refresh_btn.clicked.connect(self.refresh)
        button_row.addWidget(refresh_btn)
        button_row.addStretch(1)
        layout.addLayout(button_row)

        self.summary_label = QLabel("")
        self.summary_label.setWordWrap(True)
        layout.addWidget(self.summary_label)

        self.network_label = QLabel("")
        self.network_label.setObjectName("mutedLabel")
        self.network_label.setWordWrap(True)
        layout.addWidget(self.network_label)

        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["Module", "Check", "Earlier", "Later", "Change"])
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        layout.addWidget(self.table, stretch=1)

        self.refresh()

    # ------------------------------------------------------------------ #
    def refresh(self) -> None:
        self._entries = list_history()
        for combo in (self.older_combo, self.newer_combo):
            combo.clear()
            for entry in self._entries:
                combo.addItem(entry.label)
        if len(self._entries) >= 2:
            self.newer_combo.setCurrentIndex(0)   # newest first in the list
            self.older_combo.setCurrentIndex(1)
        self.compare_btn.setEnabled(len(self._entries) >= 2)
        if len(self._entries) < 2:
            self.summary_label.setText(
                "At least two saved runs are needed. Run the diagnostics twice to compare."
            )

    def compare_latest_two(self) -> None:
        if len(self._entries) < 2:
            self.refresh()
        if len(self._entries) < 2:
            return
        self.newer_combo.setCurrentIndex(0)
        self.older_combo.setCurrentIndex(1)
        self.compare_selected()

    def compare_selected(self) -> None:
        older_index = self.older_combo.currentIndex()
        newer_index = self.newer_combo.currentIndex()
        if older_index < 0 or newer_index < 0 or older_index >= len(self._entries):
            return
        if older_index == newer_index:
            QMessageBox.information(self, "Same run", "Please choose two different runs.")
            return

        first, second = self._entries[older_index], self._entries[newer_index]
        if first.generated_at > second.generated_at:   # always compare earlier -> later
            first, second = second, first

        try:
            old_report = load_report(first.path)
            new_report = load_report(second.path)
        except ValueError as exc:
            QMessageBox.warning(self, "Could not open report", str(exc))
            return

        self._show(compare_reports(old_report, new_report))

    # ------------------------------------------------------------------ #
    def _show(self, result: ComparisonResult) -> None:
        self.summary_label.setText(
            f"<b>{result.improved}</b> improved, <b>{result.degraded}</b> got worse, "
            f"<b>{len(result.check_diffs) - result.improved - result.degraded}</b> other change(s), "
            f"<b>{result.unchanged_count}</b> unchanged."
        )

        if result.network_changes:
            lines = [f"{c.label}: {c.old}  →  {c.new}" for c in result.network_changes]
            self.network_label.setText("Network environment changed:\n" + "\n".join(lines))
        else:
            self.network_label.setText("Network environment: no changes.")

        self.table.setRowCount(len(result.check_diffs))
        for row, diff in enumerate(result.check_diffs):
            cells = [
                diff.module,
                diff.check,
                diff.old_status or "-",
                diff.new_status or "-",
                diff.change.upper(),
            ]
            for column, text in enumerate(cells):
                item = QTableWidgetItem(text)
                if column in (2, 3) and text in STATUS_COLOR_MAP:
                    item.setForeground(QColor(STATUS_COLOR_MAP[text]))
                if column == 4:
                    item.setForeground(QColor(_CHANGE_COLORS.get(diff.change, COLOR_WARNING)))
                self.table.setItem(row, column, item)
            tooltip = f"Earlier: {diff.old_message or '-'}\nLater: {diff.new_message or '-'}"
            for column in range(5):
                self.table.item(row, column).setToolTip(tooltip)
