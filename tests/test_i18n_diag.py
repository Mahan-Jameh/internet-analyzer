"""Every sentence the correlation engine and the layered modules can show has a Persian version."""
import ast
import inspect
import re
from pathlib import Path

from app import i18n
from app.core.analyzer import ResultAnalyzer
from app.models import FullReport, ModuleReport, NetworkInfo
import test_diag_correlation as scenarios
from test_i18n import ROOT, _NOT_USER_TEXT, _render, _sample

_PERSIAN = re.compile(r"[؀-ۿ]")
_LEFTOVER = re.compile(r"(?:\b[A-Za-z]{3,}\b[ ,]+){4,}")


def _scan_diag_strings():
    found = []
    for folder in ("core", "diag"):
        for path in sorted((ROOT / "app" / folder).glob("*.py")):
            if path.name in ("__init__.py", "compare.py", "network_info.py", "neterrors.py", "i18n.py"):
                continue
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for n in ast.walk(tree):
                if isinstance(n, ast.Call):
                    fn = n.func.attr if isinstance(n.func, ast.Attribute) else getattr(n.func, "id", "")
                    for kw in n.keywords:
                        if kw.arg in ("name", "message", "text", "summary", "title"):
                            found.append((path.name, _render(kw.value)))
                    if fn == "add_evidence" and n.args:
                        found.append((path.name, _render(n.args[0])))
                    if fn == "Diagnosis" and len(n.args) > 1:
                        found.append((path.name, _render(n.args[1])))
                    if fn == "Finding" and len(n.args) > 1:
                        found.append((path.name, _render(n.args[1])))
                if isinstance(n, ast.Assign) and any(
                        isinstance(t, ast.Attribute) and t.attr == "summary" for t in n.targets):
                    found.append((path.name, _render(n.value)))
    return [(f, v) for f, v in found if v and re.search(r"[A-Za-z]{3,}", v)
            and v not in _NOT_USER_TEXT and v.strip() not in ("{}", "")]


def test_every_layered_message_template_is_translated():
    missing = [f"{f}: {v!r}" for f, v in _scan_diag_strings() if i18n._lookup(_sample(v)) is None]
    assert not missing, "Untranslated:\n" + "\n".join(missing)


def _all_summaries(monkeypatch):
    captured = []
    real = scenarios.analyze
    monkeypatch.setattr(scenarios, "analyze", lambda results: captured.append(real(results)) or captured[-1])
    for name, fn in inspect.getmembers(scenarios, inspect.isfunction):
        if name.startswith("test_") and not inspect.signature(fn).parameters:
            fn()
    return captured


def test_every_diagnosis_line_is_translated(monkeypatch):
    summaries = _all_summaries(monkeypatch)
    assert len(summaries) >= 10
    lines = set()
    for s in summaries:
        lines.add(s.headline)
        for f in s.findings:
            lines.add(f.text)
        for d in s.diagnoses:
            lines.update([d.headline, *[f"Evidence: {e}" for e in d.evidence]])
            if d.caveats:
                lines.add(f"Note: {d.caveats[0]}")
            if d.possible_causes:
                lines.add("Possible causes: " + "; ".join(d.possible_causes[:4]))
    bad = []
    for line in sorted(lines):
        fa = i18n.translate_dynamic(line, "fa")
        if not _PERSIAN.search(fa) or _LEFTOVER.search(fa):
            bad.append(f"{line!r} -> {fa!r}")
    assert not bad, "\n".join(bad)


def test_analyzer_output_for_a_real_run_is_translatable(monkeypatch):
    summary = _all_summaries(monkeypatch)[0]
    # run the analyzer wrapper end to end on an empty module list
    texts = [i.text for i in ResultAnalyzer().analyze(NetworkInfo(), [])]
    for t in texts:
        for line in t.split("\n"):
            assert _PERSIAN.search(i18n.translate_dynamic(line, "fa")), line
