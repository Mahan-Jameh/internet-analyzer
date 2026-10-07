"""
advanced_tab.py
================
Lets advanced users choose a custom target host, pick which TCP/UDP
ports to test (restricted to the fixed allow-lists), save/load named
profiles, and compare against a previously saved report.
"""

from __future__ import annotations

import json

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from app.config import Paths
from app.constants import (
    ALLOWED_TCP_PORTS,
    ALLOWED_UDP_PORTS,
    PORT_SERVICE_NAMES,
    SITE_MAX_CUSTOM_HOSTS,
    UDP_PORT_NAMES,
)
from app.core.site_reachability import sanitize_hosts
from app.logger import get_logger
from app.utils.helpers import validate_target_host

log = get_logger(__name__)


class AdvancedTab(QWidget):
    """Emits `run_requested` with (target_host, tcp_ports, udp_ports, test_sites) on Run."""

    run_requested = Signal(str, list, list, list)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.tcp_checkboxes: dict[int, QCheckBox] = {}
        self.udp_checkboxes: dict[int, QCheckBox] = {}

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        title = QLabel("Advanced Mode")
        title.setObjectName("sectionTitle")
        layout.addWidget(title)

        subtitle = QLabel(
            "Choose a custom target host and specific ports to test. Port selection is "
            "restricted to a fixed set of well known ports for safety."
        )
        subtitle.setObjectName("mutedLabel")
        subtitle.setWordWrap(True)
        layout.addWidget(subtitle)

        # --- Target host -------------------------------------------------
        target_box = QGroupBox("Target Host")
        target_layout = QHBoxLayout(target_box)
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("e.g. 1.1.1.1 or example.com (leave empty for defaults)")
        target_layout.addWidget(self.target_input)
        layout.addWidget(target_box)

        # --- Ports ---------------------------------------------------------
        ports_row = QHBoxLayout()

        tcp_box = QGroupBox("TCP Ports")
        tcp_grid = QGridLayout(tcp_box)
        for i, port in enumerate(ALLOWED_TCP_PORTS):
            service = PORT_SERVICE_NAMES.get(port, "")
            cb = QCheckBox(f"{port} ({service})")
            cb.setChecked(True)
            self.tcp_checkboxes[port] = cb
            tcp_grid.addWidget(cb, i // 3, i % 3)
        ports_row.addWidget(tcp_box, stretch=2)

        udp_box = QGroupBox("UDP Ports")
        udp_grid = QGridLayout(udp_box)
        for i, port in enumerate(ALLOWED_UDP_PORTS):
            service = UDP_PORT_NAMES.get(port, "")
            cb = QCheckBox(f"{port} ({service})")
            cb.setChecked(True)
            self.udp_checkboxes[port] = cb
            udp_grid.addWidget(cb, i // 2, i % 2)
        ports_row.addWidget(udp_box, stretch=1)

        layout.addLayout(ports_row)

        # --- Websites for the layered reachability test -------------------
        sites_box = QGroupBox("Websites to test (one per line, up to %d)" % SITE_MAX_CUSTOM_HOSTS)
        sites_layout = QVBoxLayout(sites_box)
        self.sites_input = QPlainTextEdit()
        self.sites_input.setPlaceholderText(
            "example.com\nanother-site.org\n(leave empty to use the built-in list of popular services)"
        )
        self.sites_input.setFixedHeight(90)
        sites_layout.addWidget(self.sites_input)
        layout.addWidget(sites_box)

        # --- Profiles --------------------------------------------------
        profile_box = QGroupBox("Profiles")
        profile_layout = QHBoxLayout(profile_box)

        self.profile_combo = QComboBox()
        self._reload_profiles()
        profile_layout.addWidget(self.profile_combo, stretch=1)

        load_btn = QPushButton("Load")
        load_btn.setObjectName("secondaryButton")
        load_btn.clicked.connect(self._load_profile)
        profile_layout.addWidget(load_btn)

        save_btn = QPushButton("Save Current As...")
        save_btn.setObjectName("secondaryButton")
        save_btn.clicked.connect(self._save_profile)
        profile_layout.addWidget(save_btn)

        delete_btn = QPushButton("Delete")
        delete_btn.setObjectName("secondaryButton")
        delete_btn.clicked.connect(self._delete_profile)
        profile_layout.addWidget(delete_btn)

        layout.addWidget(profile_box)

        # --- Run button --------------------------------------------------
        run_row = QHBoxLayout()
        run_row.addStretch(1)
        self.run_btn = QPushButton("Run With These Settings")
        self.run_btn.clicked.connect(self._emit_run)
        run_row.addWidget(self.run_btn)
        layout.addLayout(run_row)

        layout.addStretch(1)

    # ------------------------------------------------------------------ #
    def _emit_run(self) -> None:
        raw_target = self.target_input.text().strip()
        target = validate_target_host(raw_target)
        if raw_target and target is None:
            QMessageBox.warning(
                self, "Invalid Target",
                "The target must be a host name (example.com) or an IP address, "
                "without spaces or a leading '-'.",
            )
            return

        raw_sites = [line for line in self.sites_input.toPlainText().splitlines() if line.strip()]
        sites = sanitize_hosts(raw_sites)
        if raw_sites and len(sites) < len(raw_sites):
            QMessageBox.information(
                self, "Some entries ignored",
                f"{len(raw_sites) - len(sites)} line(s) were not valid domain names or were "
                "duplicates, and will be skipped.",
            )

        tcp_ports = [p for p, cb in self.tcp_checkboxes.items() if cb.isChecked()]
        udp_ports = [p for p, cb in self.udp_checkboxes.items() if cb.isChecked()]
        self.run_requested.emit(target or "", tcp_ports, udp_ports, sites)

    def get_current_config(self) -> dict:
        return {
            "target_host": self.target_input.text().strip(),
            "tcp_ports": [p for p, cb in self.tcp_checkboxes.items() if cb.isChecked()],
            "udp_ports": [p for p, cb in self.udp_checkboxes.items() if cb.isChecked()],
            "test_sites": [l.strip() for l in self.sites_input.toPlainText().splitlines() if l.strip()],
        }

    # ------------------------------------------------------------------ #
    def _reload_profiles(self) -> None:
        self.profile_combo.clear()
        Paths.ensure_created()
        for path in sorted(Paths.PROFILES_DIR.glob("*.json")):
            self.profile_combo.addItem(path.stem)

    def _save_profile(self) -> None:
        name, ok = QInputDialog.getText(self, "Save Profile", "Profile name:")
        if not ok or not name.strip():
            return
        safe_name = "".join(c for c in name.strip() if c.isalnum() or c in (" ", "_", "-")).strip()
        if not safe_name:
            QMessageBox.warning(self, "Invalid Name", "Please use a valid profile name.")
            return

        config = self.get_current_config()
        try:
            Paths.ensure_created()
            path = Paths.PROFILES_DIR / f"{safe_name}.json"
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(config, fh, indent=2)
            self._reload_profiles()
            index = self.profile_combo.findText(safe_name)
            if index >= 0:
                self.profile_combo.setCurrentIndex(index)
        except OSError as exc:
            QMessageBox.critical(self, "Save Failed", f"Could not save profile: {exc}")

    def _load_profile(self) -> None:
        name = self.profile_combo.currentText()
        if not name:
            QMessageBox.information(self, "No Profile", "There are no saved profiles yet.")
            return
        path = Paths.PROFILES_DIR / f"{name}.json"
        try:
            with open(path, "r", encoding="utf-8") as fh:
                config = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            QMessageBox.critical(self, "Load Failed", f"Could not load profile: {exc}")
            return

        self.target_input.setText(config.get("target_host", ""))
        self.sites_input.setPlainText("\n".join(config.get("test_sites", [])))
        tcp_selected = set(config.get("tcp_ports", []))
        for port, cb in self.tcp_checkboxes.items():
            cb.setChecked(port in tcp_selected)
        udp_selected = set(config.get("udp_ports", []))
        for port, cb in self.udp_checkboxes.items():
            cb.setChecked(port in udp_selected)

    def _delete_profile(self) -> None:
        name = self.profile_combo.currentText()
        if not name:
            return
        confirm = QMessageBox.question(
            self, "Delete Profile", f"Delete profile '{name}'? This cannot be undone."
        )
        if confirm != QMessageBox.StandardButton.Yes:
            return
        path = Paths.PROFILES_DIR / f"{name}.json"
        try:
            path.unlink(missing_ok=True)
            self._reload_profiles()
        except OSError as exc:
            QMessageBox.critical(self, "Delete Failed", f"Could not delete profile: {exc}")
