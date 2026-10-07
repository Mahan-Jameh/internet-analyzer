"""
fonts.py
========
Bundled UI fonts: **Google Sans** (Latin text) and **Vazirmatn** (Persian text).

Both are licensed under the SIL Open Font License 1.1 (see the OFL files in
``app/assets/fonts``). The Google Sans files shipped here are static
Regular/Bold instances of the official variable font, reduced to Latin
glyphs, so that in a mixed line Latin text uses Google Sans and Persian text
falls through to Vazirmatn - in both the English and the Persian UI.
"""

from __future__ import annotations

import sys
from pathlib import Path

from app.logger import get_logger

log = get_logger(__name__)

FONT_FILES = (
    "GoogleSans-Regular.ttf",
    "GoogleSans-Bold.ttf",
    "Vazirmatn-Regular.ttf",
    "Vazirmatn-Bold.ttf",
)
LATIN_FAMILY = "Google Sans"
PERSIAN_FAMILY = "Vazirmatn"
# Order matters: Qt picks the first family that has the glyph.
FALLBACKS = ("Segoe UI", "Tahoma", "Arial")

_loaded: list[str] = []


def fonts_dir() -> Path:
    base = getattr(sys, "_MEIPASS", None)
    root = Path(base) if base else Path(__file__).resolve().parents[2]
    return root / "app" / "assets" / "fonts"


def load_bundled_fonts() -> list[str]:
    """Register the bundled fonts with Qt. Never raises; returns loaded family names."""
    if _loaded:
        return list(_loaded)
    try:
        from PySide6.QtGui import QFontDatabase

        for name in FONT_FILES:
            path = fonts_dir() / name
            if not path.is_file():
                log.warning("Bundled font missing: %s", path)
                continue
            font_id = QFontDatabase.addApplicationFont(str(path))
            if font_id < 0:
                log.warning("Qt could not load font %s", path)
                continue
            for family in QFontDatabase.applicationFontFamilies(font_id):
                if family not in _loaded:
                    _loaded.append(family)
    except Exception as exc:  # noqa: BLE001 - fonts are cosmetic, never crash
        log.warning("Font loading failed: %s", exc)
    return list(_loaded)


def families() -> list[str]:
    """The font stack used everywhere: Latin first, then Persian, then system fonts."""
    return [LATIN_FAMILY, PERSIAN_FAMILY, *FALLBACKS]


def css_font_stack() -> str:
    return ", ".join(f'"{f}"' for f in families()) + ", sans-serif"


def apply_default_font(app) -> None:  # noqa: ANN001 - QApplication
    """Set the application font so widgets without a stylesheet match also use the stack."""
    from PySide6.QtGui import QFont

    font = QFont()
    font.setFamilies(families())
    font.setPixelSize(13)
    app.setFont(font)
