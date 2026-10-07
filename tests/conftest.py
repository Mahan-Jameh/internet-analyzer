"""Shared pytest setup: make `app` importable and keep test data out of the real profile."""

import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# Logs/config are written under the home directory; point it at a throw-away folder.
_TMP_HOME = tempfile.mkdtemp(prefix="icpa_test_home_")
os.environ["HOME"] = _TMP_HOME
os.environ["LOCALAPPDATA"] = _TMP_HOME
os.environ["QT_QPA_PLATFORM"] = "offscreen"


import pytest  # noqa: E402


@pytest.fixture(autouse=True)
def _english_by_default():
    """The app defaults to Persian; existing tests assert English text, so reset it for every test."""
    from app import i18n
    i18n.set_language("en")
    yield
    i18n.set_language("en")
