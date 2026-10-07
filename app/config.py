"""
config.py
=========
Handles all file-system paths and the small persisted user configuration
(advanced mode settings, saved profiles list, theme, etc).

The application purposefully stores everything under the user's local
AppData folder on Windows (or ~/.icpa on other platforms) so that it never
needs administrator rights and never writes next to the executable.
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from app.constants import (
    CONFIG_FILE_NAME,
    HISTORY_DIR_NAME,
    LOG_DIR_NAME,
    ORG_NAME,
    PROFILES_DIR_NAME,
    REPORTS_DIR_NAME,
)


def _default_data_dir() -> Path:
    """Return a per-user, per-app writable directory that never needs admin rights."""
    if sys.platform.startswith("win"):
        base = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA")
        if base:
            return Path(base) / ORG_NAME
    # macOS / Linux fallback
    return Path.home() / f".{ORG_NAME.lower()}"


class Paths:
    """Central place for all file-system locations used by the app."""

    DATA_DIR: Path = _default_data_dir()
    LOG_DIR: Path = DATA_DIR / LOG_DIR_NAME
    REPORTS_DIR: Path = DATA_DIR / REPORTS_DIR_NAME
    PROFILES_DIR: Path = DATA_DIR / PROFILES_DIR_NAME
    HISTORY_DIR: Path = DATA_DIR / HISTORY_DIR_NAME
    CONFIG_FILE: Path = DATA_DIR / CONFIG_FILE_NAME

    @classmethod
    def ensure_created(cls) -> None:
        for directory in (cls.DATA_DIR, cls.LOG_DIR, cls.REPORTS_DIR, cls.PROFILES_DIR,
                          cls.HISTORY_DIR):
            directory.mkdir(parents=True, exist_ok=True)


@dataclass
class AppSettings:
    """Small persisted settings, saved as JSON."""

    theme: str = "dark"
    language: str = "fa"          # "fa" (Persian, right-to-left) or "en"
    advanced_mode: bool = False
    last_profile: str | None = None
    window_width: int = 1180
    window_height: int = 780

    # ---------------------------------------------------------------- #
    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AppSettings":
        valid_keys = {f for f in cls.__dataclass_fields__}
        filtered = {k: v for k, v in data.items() if k in valid_keys}
        return cls(**filtered)


class ConfigManager:
    """Loads and saves :class:`AppSettings` to disk, defensively."""

    def __init__(self) -> None:
        Paths.ensure_created()
        self.settings: AppSettings = self._load()

    def _load(self) -> AppSettings:
        if Paths.CONFIG_FILE.exists():
            try:
                with open(Paths.CONFIG_FILE, "r", encoding="utf-8") as fh:
                    raw = json.load(fh)
                return AppSettings.from_dict(raw)
            except (json.JSONDecodeError, OSError, TypeError):
                # Corrupted config must never crash the app - fall back silently.
                return AppSettings()
        return AppSettings()

    def save(self) -> None:
        try:
            Paths.ensure_created()
            with open(Paths.CONFIG_FILE, "w", encoding="utf-8") as fh:
                json.dump(self.settings.to_dict(), fh, indent=2, ensure_ascii=False)
        except OSError:
            # Persisting settings is best-effort only.
            pass
