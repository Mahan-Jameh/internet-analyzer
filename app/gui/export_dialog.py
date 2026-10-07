"""
export_dialog.py
=================
A small modal dialog that lets the user pick which formats (TXT / JSON /
CSV / HTML) to export the current report as, and where to save them.
"""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
)

from app.config import Paths
from app.export.exporter import save_report
from app.i18n import tr, tr_fmt
from app.logger import get_logger
from app.models import FullReport

log = get_logger(__name__)


class ExportDialog(QDialog):
    def __init__(self, report: FullReport, parent=None) -> None:
        super().__init__(parent)
        self.report = report
        self.setWindowTitle(tr("Export Report"))
        self.setMinimumWidth(420)

        layout = QVBoxLayout(self)

        layout.addWidget(QLabel(tr("Select the format(s) to export:")))

        self.cb_txt = QCheckBox(tr("Plain Text (.txt)"))
        self.cb_json = QCheckBox(tr("JSON (.json)"))
        self.cb_csv = QCheckBox(tr("CSV (.csv)"))
        self.cb_html = QCheckBox(tr("HTML Report (.html)"))
        self.cb_html.setChecked(True)
        for cb in (self.cb_txt, self.cb_json, self.cb_csv, self.cb_html):
            layout.addWidget(cb)

        layout.addWidget(QLabel(tr("Destination folder:")))
        path_row = QHBoxLayout()
        self.path_input = QLineEdit(str(Paths.REPORTS_DIR))
        self.path_input.setLayoutDirection(Qt.LayoutDirection.LeftToRight)   # file paths are LTR
        path_row.addWidget(self.path_input)
        browse_btn = QPushButton(tr("Browse..."))
        browse_btn.setObjectName("secondaryButton")
        browse_btn.clicked.connect(self._browse)
        path_row.addWidget(browse_btn)
        layout.addLayout(path_row)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.button(QDialogButtonBox.StandardButton.Ok).setText(tr("OK"))
        buttons.button(QDialogButtonBox.StandardButton.Cancel).setText(tr("Cancel"))
        buttons.accepted.connect(self._do_export)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _browse(self) -> None:
        directory = QFileDialog.getExistingDirectory(self, tr("Choose Destination Folder"), self.path_input.text())
        if directory:
            self.path_input.setText(directory)

    def _do_export(self) -> None:
        formats = []
        if self.cb_txt.isChecked():
            formats.append("txt")
        if self.cb_json.isChecked():
            formats.append("json")
        if self.cb_csv.isChecked():
            formats.append("csv")
        if self.cb_html.isChecked():
            formats.append("html")

        if not formats:
            QMessageBox.warning(self, tr("No Format Selected"), tr("Please select at least one export format."))
            return

        directory = Path(self.path_input.text().strip() or str(Paths.REPORTS_DIR))

        saved_paths = []
        try:
            for fmt in formats:
                path = save_report(self.report, directory, fmt)
                saved_paths.append(path)
        except (OSError, ValueError) as exc:
            log.exception("Export failed")
            QMessageBox.critical(self, tr("Export Failed"), tr_fmt("Could not export report: {}", exc))
            return

        QMessageBox.information(
            self,
            tr("Export Complete"),
            tr("Saved:\n") + "\n".join(str(p) for p in saved_paths),
        )
        self.accept()
