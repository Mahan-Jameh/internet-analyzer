"""
logger.py
=========
Central logging configuration. Every module obtains its logger via
``get_logger(__name__)`` so log records are consistently formatted and
always saved to disk under the user's data directory, in addition to
being available to the in-app "detailed log" viewer through
:class:`InMemoryLogHandler`.
"""

from __future__ import annotations

import json
import logging
import logging.handlers
from collections import deque
from datetime import datetime
from typing import Deque

from app.config import Paths

_LOG_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)-28s | %(message)s"
_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

_configured = False


class InMemoryLogHandler(logging.Handler):
    """Keeps the last N log records in memory so the GUI can show them live."""

    def __init__(self, capacity: int = 5000) -> None:
        super().__init__()
        self.capacity = capacity
        self.records: Deque[str] = deque(maxlen=capacity)

    def emit(self, record: logging.LogRecord) -> None:
        try:
            self.records.append(self.format(record))
        except Exception:
            # A logging handler must never raise.
            pass

    def get_text(self) -> str:
        return "\n".join(self.records)


class JsonLinesHandler(logging.handlers.RotatingFileHandler):
    """One JSON object per line: time, level, logger, message and - for test results - ``event``."""

    def emit(self, record: logging.LogRecord) -> None:
        try:
            entry = {
                "time": datetime.fromtimestamp(record.created).isoformat(timespec="milliseconds"),
                "level": record.levelname, "logger": record.name, "message": record.getMessage(),
            }
            event = getattr(record, "event", None)
            if event is not None:
                entry["event"] = event
            self.stream = self.stream or self._open()
            self.stream.write(json.dumps(entry, ensure_ascii=False, default=str) + "\n")
            self.flush()
        except Exception:
            pass  # a logging handler must never raise


_memory_handler = InMemoryLogHandler()


def _configure_root() -> None:
    global _configured
    if _configured:
        return

    Paths.ensure_created()
    log_file = Paths.LOG_DIR / f"icpa_{datetime.now():%Y%m%d}.log"

    formatter = logging.Formatter(_LOG_FORMAT, datefmt=_DATE_FORMAT)

    file_handler = logging.handlers.RotatingFileHandler(
        log_file, maxBytes=2_000_000, backupCount=5, encoding="utf-8"
    )
    file_handler.setFormatter(formatter)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)

    _memory_handler.setFormatter(formatter)

    root = logging.getLogger("icpa")
    root.setLevel(logging.DEBUG)
    root.addHandler(file_handler)
    root.addHandler(console_handler)
    json_handler = JsonLinesHandler(Paths.LOG_DIR / f"icpa_{datetime.now():%Y%m%d}.jsonl",
                                    maxBytes=4_000_000, backupCount=3, encoding="utf-8")
    root.addHandler(json_handler)
    root.addHandler(_memory_handler)
    root.propagate = False

    _configured = True


def get_logger(name: str) -> logging.Logger:
    """Return a namespaced logger, e.g. ``icpa.core.dns_test``."""
    _configure_root()
    short_name = name.replace("app.", "")
    return logging.getLogger(f"icpa.{short_name}")


def get_memory_log_text() -> str:
    """Return every log line captured so far, for the in-app log viewer / export."""
    _configure_root()
    return _memory_handler.get_text()
