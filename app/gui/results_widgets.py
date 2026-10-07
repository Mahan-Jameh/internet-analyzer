"""
results_widgets.py
===================
Small reusable Qt widgets used to visualize test results: color coded
status badges, expandable per-module result cards, and the network
information grid shown on the home screen.
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from app.gui.styles import (
    COLOR_BG_CARD,
    COLOR_BORDER,
    COLOR_TEXT_MUTED,
    STATUS_COLOR_MAP,
    STATUS_SYMBOL_MAP,
)
from app.models import CheckResult, ModuleReport, NetworkInfo


class StatusBadge(QLabel):
    """A small colored pill showing a status value (OK / WARNING / FAILED / UNKNOWN)."""

    def __init__(self, status_value: str = "UNKNOWN", parent: QWidget | None = None,
                 text: str | None = None) -> None:
        super().__init__(parent)
        self.set_status(status_value, text)

    def set_status(self, status_value: str, text: str | None = None) -> None:
        """``text`` overrides the shown label (e.g. "NOT TESTED") while keeping the color."""
        color = STATUS_COLOR_MAP.get(status_value, STATUS_COLOR_MAP["UNKNOWN"])
        symbol = STATUS_SYMBOL_MAP.get(status_value, "•")
        self.setText(f" {symbol} {text or status_value} ")
        self.setStyleSheet(
            f"background-color:{color}; color:#12131a; border-radius:9px; "
            f"padding:2px 10px; font-weight:700;"
        )
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)


class CheckResultRow(QFrame):
    """A single check result line: name, badge, message, duration."""

    def __init__(self, check: CheckResult, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(8, 4, 8, 4)

        badge = StatusBadge(check.status.value)
        badge.setFixedWidth(100)
        layout.addWidget(badge)

        text_col = QVBoxLayout()
        name_label = QLabel(check.name)
        name_label.setStyleSheet("font-weight:600;")
        text_col.addWidget(name_label)

        if check.message:
            msg_label = QLabel(check.message)
            msg_label.setStyleSheet(f"color:{COLOR_TEXT_MUTED};")
            msg_label.setWordWrap(True)
            text_col.addWidget(msg_label)

        layout.addLayout(text_col, stretch=1)

        if check.duration_ms is not None:
            duration_label = QLabel(f"{check.duration_ms:.0f} ms")
            duration_label.setStyleSheet(f"color:{COLOR_TEXT_MUTED};")
            layout.addWidget(duration_label)


class ModuleResultCard(QFrame):
    """An expandable/collapsible card showing one module's overall status and all its checks."""

    def __init__(self, report: ModuleReport, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("moduleCard")
        self.setStyleSheet(
            f"#moduleCard {{ background-color:{COLOR_BG_CARD}; border:1px solid {COLOR_BORDER}; "
            f"border-radius:10px; }}"
        )
        self._expanded = True

        outer = QVBoxLayout(self)
        outer.setContentsMargins(12, 10, 12, 10)

        header = QHBoxLayout()
        self.toggle_btn = QToolButton()
        self.toggle_btn.setArrowType(Qt.ArrowType.DownArrow)
        self.toggle_btn.setStyleSheet("border:none; background:transparent;")
        self.toggle_btn.clicked.connect(self._toggle)
        header.addWidget(self.toggle_btn)

        title = QLabel(report.module_name)
        title.setObjectName("sectionTitle")
        header.addWidget(title)
        header.addStretch(1)
        header.addWidget(StatusBadge(report.overall_status.value))
        outer.addLayout(header)

        self.body = QWidget()
        body_layout = QVBoxLayout(self.body)
        body_layout.setContentsMargins(20, 6, 0, 0)
        for check in report.checks:
            body_layout.addWidget(CheckResultRow(check))
        outer.addWidget(self.body)

    def _toggle(self) -> None:
        self._expanded = not self._expanded
        self.body.setVisible(self._expanded)
        self.toggle_btn.setArrowType(
            Qt.ArrowType.DownArrow if self._expanded else Qt.ArrowType.RightArrow
        )


class PlaceholderCard(QFrame):
    """A gray card for a module that has not produced a result (yet): WAITING / RUNNING / NOT TESTED."""

    def __init__(self, module_name: str, label: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("placeholderCard")
        self.setStyleSheet(
            f"#placeholderCard {{ background-color:{COLOR_BG_CARD}; border:1px dashed {COLOR_BORDER}; "
            f"border-radius:10px; }}"
        )
        layout = QHBoxLayout(self)
        layout.setContentsMargins(14, 10, 14, 10)
        title = QLabel(module_name)
        title.setObjectName("sectionTitle")
        layout.addWidget(title)
        layout.addStretch(1)
        self.badge = StatusBadge("UNKNOWN", text=label)
        layout.addWidget(self.badge)

    def set_label(self, label: str) -> None:
        self.badge.set_status("UNKNOWN", label)


class InfoBox(QFrame):
    """A single labelled value box used in the home screen's network info grid."""

    def __init__(self, label: str, value: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setStyleSheet(
            f"background-color:{COLOR_BG_CARD}; border-radius:8px; border:1px solid {COLOR_BORDER};"
        )
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 10, 14, 10)

        label_widget = QLabel(label.upper())
        label_widget.setStyleSheet(f"color:{COLOR_TEXT_MUTED}; font-size:11px; letter-spacing:1px;")
        layout.addWidget(label_widget)

        self.value_widget = QLabel(value)
        self.value_widget.setStyleSheet("font-size:16px; font-weight:700;")
        self.value_widget.setWordWrap(True)
        layout.addWidget(self.value_widget)

    def set_value(self, value: str) -> None:
        self.value_widget.setText(value)


class NetworkInfoGrid(QWidget):
    """The grid of info boxes shown on the home screen."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.grid = QGridLayout(self)
        self.grid.setSpacing(10)

        self.boxes: dict[str, InfoBox] = {}
        fields = [
            "Internet Status", "Public IP", "ISP", "Country", "City",
            "IPv4 Available", "IPv6 Available", "DNS Servers", "Network Adapter", "Gateway",
        ]
        for i, field_name in enumerate(fields):
            box = InfoBox(field_name, "Loading...")
            self.boxes[field_name] = box
            self.grid.addWidget(box, i // 3, i % 3)

    def update_info(self, info: NetworkInfo) -> None:
        self.boxes["Internet Status"].set_value("Connected" if info.internet_reachable else "Not Connected")
        self.boxes["Public IP"].set_value(info.public_ip or "N/A")
        self.boxes["ISP"].set_value(info.isp or "N/A")
        self.boxes["Country"].set_value(info.country or "N/A")
        self.boxes["City"].set_value(info.city or "N/A")
        self.boxes["IPv4 Available"].set_value("Yes" if info.ipv4_available else "No")
        self.boxes["IPv6 Available"].set_value("Yes" if info.ipv6_available else "No")
        self.boxes["DNS Servers"].set_value(", ".join(info.dns_servers) if info.dns_servers else "N/A")
        self.boxes["Network Adapter"].set_value(info.adapter_name or "N/A")
        self.boxes["Gateway"].set_value(info.gateway or "N/A")
