"""Tests for the Persian translation layer and the language-aware exports."""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

from app import i18n
from app.export.exporter import to_csv, to_html, to_json, to_txt
from app.i18n_fa import DYNAMIC_FA, UI_FA
from app.models import (
    CheckResult, FullReport, Interpretation, ModuleReport, NetworkInfo, Status,
)

ROOT = Path(__file__).resolve().parent.parent

# Strings in the test modules that are protocol data or technical identifiers, not user text.
_NOT_USER_TEXT = {
    "Mozilla/5.0 ICPA-diagnostic", "gzip, br, deflate",
    "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
    "^(Ethernet adapter|Wireless LAN adapter) (.+):\\s*$",
    "{domain}: {exc.__class__.__name__}", "{domain}: NXDOMAIN", "{domain}: timeout",
    "{d} ({', '.join(outliers[d])})", "resolve via", "TLS 1.3", "TLS 1.2",
    "TCP 443", "UDP 443", "{display_name}: {exc}", "'{}'", "{}",
    "Mozilla/5.0", "DNS Servers", "Default Gateway", "Cloudflare",
}


def _render(node) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        return "".join(v.value if isinstance(v, ast.Constant) else "{}" for v in node.values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = _render(node.left), _render(node.right)
        if left is not None and right is not None:
            return left + right
    return None


def _user_facing_strings() -> list[tuple[str, str]]:
    """
    Every message / name the test modules and the analyzer hand to CheckResult,
    Interpretation or a progress callback, taken straight from the source.
    """
    found: list[tuple[str, str]] = []
    for path in sorted((ROOT / "app" / "core").glob("*.py")):
        if path.name in ("__init__.py", "compare.py", "network_info.py"):
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for call in ast.walk(tree):
            if not isinstance(call, ast.Call):
                continue
            for kw in call.keywords:
                if kw.arg in ("name", "message", "text"):
                    value = _render(kw.value)
                    if value:
                        found.append((path.name, value))
    # The analyzer passes its sentences positionally, so take every long sentence in it.
    analyzer = ast.parse((ROOT / "app" / "core" / "analyzer.py").read_text(encoding="utf-8"))
    docstrings = {
        id(n.body[0].value) for n in ast.walk(analyzer)
        if isinstance(n, (ast.Module, ast.FunctionDef, ast.ClassDef)) and n.body
        and isinstance(n.body[0], ast.Expr) and isinstance(getattr(n.body[0], "value", None), ast.Constant)
    }
    for node in ast.walk(analyzer):
        if id(node) in docstrings or not isinstance(node, (ast.Constant, ast.JoinedStr)):
            continue
        value = _render(node)
        if not value or len(value.split()) < 4:
            continue
        if value[0] in " .)" or value.rstrip().endswith(("(", ":", "such as")):
            continue                      # a fragment of a sentence assembled from several pieces
        found.append(("analyzer.py", value))
    return found


def _sample(template: str) -> str:
    """Turn an f-string template (with {} holes) into a realistic sample message."""
    return template.replace("{}", "42")


def test_every_check_message_has_a_persian_translation():
    missing = []
    for file_name, template in _user_facing_strings():
        if template in _NOT_USER_TEXT or not re.search(r"[A-Za-z]{3,}", template):
            continue
        # Messages built from several pieces, or that are only a value, are covered by their parts.
        if template.strip() in ("{}", "") or template.startswith("{") and template.endswith("}"):
            continue
        # A translation may legitimately equal the English text (e.g. "HTTPS"), so check for a
        # table entry instead of comparing strings.
        if i18n._lookup(_sample(template)) is None:
            missing.append(f"{file_name}: {template!r}")
    assert not missing, "Untranslated messages:\n" + "\n".join(missing)


def test_translation_templates_are_consistent():
    for english, persian in {**DYNAMIC_FA, **UI_FA}.items():
        holes = english.count("{}")
        used = {int(n) for n in re.findall(r"\{(\d+)\}", persian)}
        if holes:
            assert used <= set(range(1, holes + 1)), f"bad placeholder numbers in {english!r}"
            assert used, f"Persian text drops every value of {english!r}"
        else:
            assert not used, f"unexpected placeholders in {english!r}"


def test_translate_dynamic_fills_values_and_nested_words():
    assert i18n.translate_dynamic("Ping 1.1.1.1", "fa") == "پینگ 1.1.1.1"
    assert "42" in i18n.translate_dynamic("Reachable, average RTT 42 ms.", "fa")
    nested = i18n.translate_dynamic(
        "Signs of a block page: HTTP 451 (unavailable for legal reasons); "
        "page embeds an iframe from a private address.", "fa")
    assert "HTTP 451" in nested and "unavailable" not in nested and "iframe" in nested
    assert "باز" in i18n.translate_dynamic("OPEN - 12 ms", "fa")   # state word inside a template


def test_unknown_text_is_left_alone_and_english_is_untouched():
    assert i18n.translate_dynamic("Something we never wrote", "fa") == "Something we never wrote"
    assert i18n.translate_dynamic("Ping 1.1.1.1", "en") == "Ping 1.1.1.1"
    assert i18n.tr("Home", "en") == "Home" and i18n.tr("Home", "fa") == "خانه"
    assert i18n.tr_fmt("Run {} of {}: ", 2, 5, lang="en") == "Run 2 of 5: "
    assert i18n.tr_fmt("Run {} of {}: ", 2, 5, lang="fa") == "اجرای 2 از 5: "


def test_unknown_language_falls_back_to_default():
    assert i18n.set_language("xx") == i18n.DEFAULT_LANGUAGE
    assert i18n.is_rtl("fa") and not i18n.is_rtl("en")


@pytest.fixture
def report() -> FullReport:
    module = ModuleReport(module_name="DNS Test")
    module.add(CheckResult(name="Ping 1.1.1.1", status=Status.WARNING,
                           message="Partial packet loss: 25% of packets lost.", duration_ms=12.0))
    module.add(CheckResult(name="<script>alert(1)</script>", status=Status.OK,
                           message="=HYPERLINK(\"http://evil\")"))
    module.finish()
    return FullReport(
        network_info=NetworkInfo(public_ip="1.2.3.4", isp="Test ISP", ipv4_available=True,
                                 internet_reachable=True),
        modules=[module],
        interpretations=[Interpretation(severity=Status.OK,
                                        text="HTTP/2 negotiated successfully.")],
        duration_seconds=3.0,
    )


def test_persian_html_is_rtl_escaped_and_translated(report):
    html_text = to_html(report, "fa")
    assert 'dir="rtl"' in html_text and 'lang="fa"' in html_text
    assert "پینگ 1.1.1.1" in html_text
    assert "هشدار" in html_text                 # WARNING badge
    assert "<script>alert(1)</script>" not in html_text   # still escaped
    assert "&lt;script&gt;" in html_text


def test_english_html_stays_ltr(report):
    html_text = to_html(report, "en")
    assert 'dir="ltr"' in html_text and "Ping 1.1.1.1" in html_text


def test_persian_txt_and_csv(report):
    txt = to_txt(report, "fa")
    assert "اطلاعات شبکه" in txt and "پینگ 1.1.1.1" in txt
    assert "HTTP/2 با موفقیت مذاکره شد." in txt
    csv_text = to_csv(report, "fa")
    assert csv_text.splitlines()[0].startswith("Module,Check,Status")   # headers stay English
    assert "پینگ 1.1.1.1" in csv_text
    assert "'=HYPERLINK" in csv_text                                    # formula guard kept


def test_json_is_never_translated(report):
    data = to_json(report, "fa")
    assert "Ping 1.1.1.1" in data and "پینگ" not in data


def _synthetic_modules() -> list[ModuleReport]:
    """Reports that make the analyzer produce its sentences that embed names and numbers."""
    def module(name, *checks):
        m = ModuleReport(module_name=name)
        for check in checks:
            m.add(check)
        return m

    return [
        module("DNS Test",
               CheckResult("Resolve via Google (8.8.8.8)", Status.FAILED, "x"),
               CheckResult("Resolve via Quad9 (9.9.9.9)", Status.FAILED, "x")),
        module("TCP Port Scanner",
               CheckResult("TCP 443 (HTTPS)", Status.OK, "OPEN - 20 ms",
                           details={"port": 443, "state": "open"}),
               CheckResult("TCP 80 (HTTP)", Status.WARNING, "TIMEOUT",
                           details={"port": 80, "state": "timeout"}),
               CheckResult("TCP 22 (SSH)", Status.FAILED, "RESET",
                           details={"port": 22, "state": "reset"})),
        module("Latency Test",
               CheckResult("Latency to Google", Status.WARNING, "x",
                           details={"average_ms": 400, "loss_percent": 30})),
        module("MTU Test",
               CheckResult("Path MTU Discovery", Status.WARNING, "x", details={"estimated_mtu": 1400})),
        module("DNS Test 2"),
        module("Website Reachability",
               CheckResult("Control vs Test Comparison", Status.WARNING, "x",
                           details={"failed_stages": {"dns": 1, "tls": 2}})),
    ]


def test_analyzer_sentences_with_embedded_values_are_fully_translated():
    from app.core.analyzer import ResultAnalyzer
    info = NetworkInfo(internet_reachable=True, ipv4_available=True, ipv6_available=False)
    texts = [i.text for i in ResultAnalyzer().analyze(info, _synthetic_modules())]
    assert len(texts) >= 6
    persian = re.compile(r"[\u0600-\u06FF]")
    leftover_english = re.compile(r"(?:\b[A-Za-z]{3,}\b[ ,]+){4,}")
    for text in texts:
        translated = i18n.translate_dynamic(text, "fa")
        assert persian.search(translated), f"not translated: {text}"
        assert not leftover_english.search(translated), f"English left over in: {translated}"
        assert "Resolve via" not in translated, f"list of names only half translated: {translated}"
