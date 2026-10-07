"""
history.py
==========
Automatically keeps every completed diagnostic run as a JSON file so
that runs can be compared later. Files live under the per-user data
directory and the oldest ones are pruned beyond a fixed limit.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from app.config import Paths
from app.constants import HISTORY_MAX_FILES
from app.logger import get_logger
from app.models import FullReport

log = get_logger(__name__)


@dataclass(frozen=True)
class HistoryEntry:
    path: Path
    generated_at: datetime
    label: str          # shown in the UI
    profile_name: str | None


def save_to_history(report: FullReport, directory: Path | None = None) -> Path | None:
    """Store ``report`` as JSON. Returns the file path, or None if saving failed."""
    directory = directory or Paths.HISTORY_DIR
    try:
        directory.mkdir(parents=True, exist_ok=True)
        stamp = report.generated_at.strftime("%Y%m%d_%H%M%S_%f")
        path = directory / f"run_{stamp}.json"
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(report.to_dict(), fh, indent=2, ensure_ascii=False)
        _prune(directory)
        return path
    except OSError as exc:
        log.error("Could not save report to history: %s", exc)
        return None


def _prune(directory: Path, keep: int = HISTORY_MAX_FILES) -> None:
    files = sorted(directory.glob("run_*.json"))
    for old in files[:-keep] if len(files) > keep else []:
        try:
            old.unlink()
        except OSError:
            pass


def normalize_report_dict(data: dict[str, Any]) -> dict[str, Any]:
    """
    Bring any saved report up to the shape of schema version 2 *without* losing or inventing data.
    Version-1 files (no ``schema_version``) get empty ``tests`` / ``diagnoses`` and a ``run`` block
    rebuilt from their top-level fields; unknown future keys are left untouched.
    """
    out = dict(data)
    version = out.get("schema_version")
    out["schema_version"] = version if isinstance(version, int) else 1
    out.setdefault("run", {k: out.get(k) for k in
                           ("generated_at", "duration_seconds", "cancelled", "profile_name", "target_host")})
    for key in ("tests", "diagnoses", "key_findings", "interpretations", "modules"):
        if not isinstance(out.get(key), list):
            out[key] = []
    if not isinstance(out.get("summary"), dict):
        out["summary"] = {}
    if not isinstance(out.get("network_info"), dict):
        out["network_info"] = {}
    return out


def load_report(path: Path) -> dict[str, Any]:
    """Load a saved report as a plain dict. Raises ValueError for unreadable files."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Could not read report '{path.name}': {exc}") from exc
    if not isinstance(data, dict) or "modules" not in data:
        raise ValueError(f"'{path.name}' is not a valid diagnostic report.")
    return normalize_report_dict(data)


def list_history(directory: Path | None = None) -> list[HistoryEntry]:
    """All readable saved runs, newest first. Corrupt files are skipped."""
    directory = directory or Paths.HISTORY_DIR
    entries: list[HistoryEntry] = []
    if not directory.exists():
        return entries
    for path in directory.glob("run_*.json"):
        try:
            data = load_report(path)
            generated = datetime.fromisoformat(data.get("generated_at", ""))
        except (ValueError, TypeError):
            continue
        profile = data.get("profile_name")
        label = generated.strftime("%Y-%m-%d %H:%M:%S")
        target = data.get("target_host")
        if target:
            label += f"  -  {target}"
        entries.append(HistoryEntry(path, generated, label, profile))
    entries.sort(key=lambda e: e.generated_at, reverse=True)
    return entries
