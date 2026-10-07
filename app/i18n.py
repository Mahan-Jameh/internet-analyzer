"""
i18n.py
=======
A tiny translation layer (English / Persian) with right-to-left support.

Design
------
* Report data (check names, messages, JSON, history files, comparisons) always
  stays in English. That keeps saved reports comparable and machine-readable.
* Translation happens only when something is *shown* (GUI, TXT/HTML/CSV export):
    - :func:`tr`                 fixed interface strings
    - :func:`tr_fmt`             interface strings with ``{}`` values
    - :func:`translate_dynamic`  messages produced by the tests / analyzer, matched
                                 against templates (see ``i18n_fa.py``)
    - :func:`tr_status`          OK / WARNING / FAILED ... badges
* Anything without a translation is shown in English, never lost or broken.
"""

from __future__ import annotations

import re
from functools import lru_cache
from typing import Optional

from app.i18n_fa import DYNAMIC_FA, STATUS_FA, UI_FA, WORDS_FA

LANG_EN = "en"
LANG_FA = "fa"
SUPPORTED_LANGUAGES: dict[str, str] = {LANG_EN: "English", LANG_FA: "فارسی"}
DEFAULT_LANGUAGE = LANG_FA
RTL_LANGUAGES = {LANG_FA}

_current_language: str = DEFAULT_LANGUAGE


# --------------------------------------------------------------------------- #
# current language
# --------------------------------------------------------------------------- #
def set_language(code: str) -> str:
    """Select the active language. Unknown codes fall back to the default."""
    global _current_language
    _current_language = code if code in SUPPORTED_LANGUAGES else DEFAULT_LANGUAGE
    return _current_language


def get_language() -> str:
    return _current_language


def is_rtl(lang: Optional[str] = None) -> bool:
    return (lang or _current_language) in RTL_LANGUAGES


def _is_fa(lang: Optional[str]) -> bool:
    return (lang or _current_language) == LANG_FA


# --------------------------------------------------------------------------- #
# fixed interface strings
# --------------------------------------------------------------------------- #
def tr(text: str, lang: Optional[str] = None) -> str:
    """Translate a fixed interface string (returns ``text`` if there is no translation)."""
    if not _is_fa(lang):
        return text
    return UI_FA.get(text) or DYNAMIC_FA.get(text) or WORDS_FA.get(text) or text


def _fill(template: str, args: tuple, numbered: bool) -> str:
    if numbered:
        return re.sub(r"\{(\d+)\}", lambda m: str(args[int(m.group(1)) - 1])
                      if 0 < int(m.group(1)) <= len(args) else m.group(0), template)
    parts = template.split("{}")
    out = [parts[0]]
    for i, part in enumerate(parts[1:]):
        out.append(str(args[i]) if i < len(args) else "{}")
        out.append(part)
    return "".join(out)


def tr_fmt(text: str, *args: object, lang: Optional[str] = None) -> str:
    """
    Translate ``text`` (written with ``{}`` placeholders) and insert ``args``.
    English keeps ``{}`` placeholders; Persian templates use ``{1}``, ``{2}`` ...
    """
    if _is_fa(lang):
        translated = UI_FA.get(text) or DYNAMIC_FA.get(text)
        if translated:
            return _fill(translated, args, numbered=True)
    return _fill(text, args, numbered=False)


def tr_status(value: str, lang: Optional[str] = None) -> str:
    """Translate a status or state word (OK, WARNING, open, IMPROVED ...)."""
    if not _is_fa(lang):
        return value
    return STATUS_FA.get(value, value)


# --------------------------------------------------------------------------- #
# messages produced by the tests and the analyzer
# --------------------------------------------------------------------------- #
class _Template:
    __slots__ = ("regex", "persian", "weight")

    def __init__(self, english: str, persian: str) -> None:
        parts = english.split("{}")
        self.regex = re.compile("^" + "(.+?)".join(re.escape(p) for p in parts) + "$", re.DOTALL)
        self.persian = persian
        self.weight = sum(len(p) for p in parts)   # more literal text = more specific


def _build_templates() -> tuple[dict[str, str], list[_Template]]:
    exact: dict[str, str] = {}
    templates: list[_Template] = []
    for english, persian in DYNAMIC_FA.items():
        if "{}" in english:
            templates.append(_Template(english, persian))
        else:
            exact[english] = persian
    templates.sort(key=lambda t: t.weight, reverse=True)
    return exact, templates


_EXACT, _TEMPLATES = _build_templates()

_JOINERS = (("; ", "؛ "), (" | ", " | "), (", ", "، "))


def _lookup(text: str) -> Optional[str]:
    """Translate ``text`` as a whole, or return None."""
    hit = _EXACT.get(text) or WORDS_FA.get(text) or STATUS_FA.get(text) or UI_FA.get(text)
    if hit:
        return hit
    for template in _TEMPLATES:
        match = template.regex.match(text)
        if match:
            groups = [_translate_part(g) for g in match.groups()]
            return _fill(template.persian, tuple(groups), numbered=True)
    return None


def _translate_part(part: str) -> str:
    """Translate a value captured inside a template (may itself be a list of phrases)."""
    # A list such as "Resolve via A (1.1.1.1), Resolve via B (2.2.2.2)" must be split first,
    # otherwise a lazy template match could swallow the whole list as one name.
    for english_sep, persian_sep in _JOINERS:
        if english_sep in part:
            pieces = part.split(english_sep)
            translated = [_lookup(p) for p in pieces]
            if all(t is not None for t in translated):
                return persian_sep.join(translated)
    whole = _lookup(part)
    if whole is not None:
        return whole
    for english_sep, persian_sep in _JOINERS:
        if english_sep in part:
            pieces = part.split(english_sep)
            translated = [_lookup(p) for p in pieces]
            if any(t is not None for t in translated):
                return persian_sep.join(t if t is not None else p for t, p in zip(translated, pieces))
    return part


@lru_cache(maxsize=4096)
def _translate_dynamic_fa(text: str) -> str:
    stripped = text.strip()
    if not stripped:
        return text
    result = _lookup(stripped)
    if result is None:
        # Several sentences joined by a space or newline: translate line by line.
        if "\n" in stripped:
            return "\n".join(_translate_dynamic_fa(line) for line in stripped.split("\n"))
        return text
    return result


def translate_dynamic(text: str, lang: Optional[str] = None) -> str:
    """Translate a test / analyzer message for display. Unknown text is returned unchanged."""
    if not text or not _is_fa(lang):
        return text
    return _translate_dynamic_fa(text)


# --------------------------------------------------------------------------- #
# Qt integration
# --------------------------------------------------------------------------- #
def apply_to_application(app) -> None:   # noqa: ANN001 - QApplication, imported lazily
    """
    Apply the active language to a running ``QApplication``: layout direction
    (right-to-left for Persian) and Qt's own standard dialog texts, when available.
    """
    from PySide6.QtCore import QLibraryInfo, QLocale, QTranslator, Qt

    app.setLayoutDirection(Qt.LayoutDirection.RightToLeft if is_rtl() else Qt.LayoutDirection.LeftToRight)

    # Remove the previous Qt translator, if any.
    previous = getattr(app, "_icpa_qt_translator", None)
    if previous is not None:
        app.removeTranslator(previous)
        app._icpa_qt_translator = None

    if _is_fa(None):
        QLocale.setDefault(QLocale(QLocale.Language.Persian, QLocale.Country.Iran))
        translator = QTranslator(app)
        path = QLibraryInfo.path(QLibraryInfo.LibraryPath.TranslationsPath)
        if translator.load("qtbase_fa", path):
            app.installTranslator(translator)
            app._icpa_qt_translator = translator
    else:
        QLocale.setDefault(QLocale(QLocale.Language.English, QLocale.Country.UnitedStates))
