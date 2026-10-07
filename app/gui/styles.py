"""
styles.py
=========
A single, self contained dark theme stylesheet plus the color palette
used consistently across every widget (status colors, backgrounds).
"""

from __future__ import annotations

from app.gui.fonts import css_font_stack

COLOR_BG = "#1c1d24"
COLOR_BG_PANEL = "#25262f"
COLOR_BG_CARD = "#2a2c38"
COLOR_BORDER = "#3a3c48"
COLOR_TEXT = "#e8e8ec"
COLOR_TEXT_MUTED = "#9a9ba5"
COLOR_ACCENT = "#4c8bf5"

COLOR_OK = "#2ecc71"
COLOR_WARNING = "#f1c40f"
COLOR_FAILED = "#e74c3c"
COLOR_UNKNOWN = "#8a8d99"

STATUS_COLOR_MAP = {
    "OK": COLOR_OK,
    "WARNING": COLOR_WARNING,
    "FAILED": COLOR_FAILED,
    "UNKNOWN": COLOR_UNKNOWN,
}

STATUS_SYMBOL_MAP = {
    "OK": "\u2714",       # ✔
    "WARNING": "\u26A0",  # ⚠
    "FAILED": "\u2716",   # ✖
    "UNKNOWN": "\u2022",  # •
}

DARK_STYLESHEET = f"""
QMainWindow, QWidget {{
    background-color: {COLOR_BG};
    color: {COLOR_TEXT};
    font-family: {css_font_stack()};
    font-size: 13px;
}}

QLabel {{
    background: transparent;
}}

QTabWidget::pane {{
    border: 1px solid {COLOR_BORDER};
    border-radius: 8px;
    top: -1px;
}}

QTabBar::tab {{
    background: {COLOR_BG_PANEL};
    color: {COLOR_TEXT_MUTED};
    padding: 10px 20px;
    margin-right: 2px;
    border-top-left-radius: 8px;
    border-top-right-radius: 8px;
}}

QTabBar::tab:selected {{
    background: {COLOR_BG_CARD};
    color: {COLOR_TEXT};
    font-weight: 600;
}}

QPushButton {{
    background-color: {COLOR_ACCENT};
    color: white;
    border: none;
    border-radius: 6px;
    padding: 9px 18px;
    font-weight: 600;
}}

QPushButton:hover {{
    background-color: #6a9ff8;
}}

QPushButton:disabled {{
    background-color: #43495c;
    color: #9a9ba5;
}}

QPushButton#secondaryButton {{
    background-color: {COLOR_BG_CARD};
    color: {COLOR_TEXT};
    border: 1px solid {COLOR_BORDER};
}}

QPushButton#secondaryButton:hover {{
    background-color: #33353f;
}}

QLineEdit, QComboBox, QSpinBox, QPlainTextEdit, QTextEdit {{
    background-color: {COLOR_BG_CARD};
    border: 1px solid {COLOR_BORDER};
    border-radius: 6px;
    padding: 6px 8px;
    color: {COLOR_TEXT};
}}

QGroupBox {{
    border: 1px solid {COLOR_BORDER};
    border-radius: 8px;
    margin-top: 14px;
    padding: 10px;
    font-weight: 600;
}}

QGroupBox::title {{
    subcontrol-origin: margin;
    left: 10px;
    padding: 0 6px;
    color: {COLOR_TEXT_MUTED};
}}

QProgressBar {{
    background-color: {COLOR_BG_CARD};
    border: 1px solid {COLOR_BORDER};
    border-radius: 6px;
    text-align: center;
    color: {COLOR_TEXT};
    height: 20px;
}}

QProgressBar::chunk {{
    background-color: {COLOR_ACCENT};
    border-radius: 6px;
}}

QScrollArea {{
    border: none;
}}

QCheckBox {{
    spacing: 8px;
}}

QLabel#sectionTitle {{
    font-size: 16px;
    font-weight: 700;
    color: {COLOR_TEXT};
}}

QLabel#mutedLabel {{
    color: {COLOR_TEXT_MUTED};
}}

QListWidget, QTreeWidget {{
    background-color: {COLOR_BG_PANEL};
    border: 1px solid {COLOR_BORDER};
    border-radius: 8px;
}}
"""
