"""
logs_tab.py
===========
Shows the in-memory application log (mirrored to disk automatically by
logger.py) with a refresh button and the ability to save the currently
displayed log to a text file.
"""

from __future__ import annotations

from PySide6.QtWidgets import (
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from app.config import Paths
from app.logger import get_memory_log_text


class LogsTab(QWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(12)

        header = QHBoxLayout()
        title = QLabel("Detailed Logs")
        title.setObjectName("sectionTitle")
        header.addWidget(title)
        header.addStretch(1)

        refresh_btn = QPushButton("Refresh")
        refresh_btn.setObjectName("secondaryButton")
        refresh_btn.clicked.connect(self.refresh)
        header.addWidget(refresh_btn)

        save_btn = QPushButton("Save Log As...")
        save_btn.setObjectName("secondaryButton")
        save_btn.clicked.connect(self._save_log)
        header.addWidget(save_btn)
        layout.addLayout(header)

        info = QLabel(f"Log files are also automatically saved to: {Paths.LOG_DIR}")
        info.setObjectName("mutedLabel")
        info.setWordWrap(True)
        layout.addWidget(info)

        self.log_view = QPlainTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setStyleSheet("font-family: Consolas, monospace; font-size:12px;")
        layout.addWidget(self.log_view, stretch=1)

        self.refresh()

    def refresh(self) -> None:
        self.log_view.setPlainText(get_memory_log_text())
        scrollbar = self.log_view.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())

    def _save_log(self) -> None:
        path, _ = QFileDialog.getSaveFileName(
            self, "Save Log", str(Paths.LOG_DIR / "exported_log.txt"), "Text Files (*.txt)"
        )
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(self.log_view.toPlainText())
            QMessageBox.information(self, "Saved", f"Log saved to:\n{path}")
        except OSError as exc:
            QMessageBox.critical(self, "Save Failed", f"Could not save log: {exc}")
