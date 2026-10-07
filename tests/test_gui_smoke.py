"""The GUI renders a layered report (both languages) without raising."""
import pytest

pytest.importorskip("PySide6")

from datetime import datetime

from PySide6.QtWidgets import QApplication, QLabel

from app import i18n
from app.core.analyzer import ResultAnalyzer
from app.diag.adapter import check_from_result
from app.diag.results import TechnicalStatus as S, TestResult
from app.gui.fonts import load_bundled_fonts
from app.gui.results_widgets import NetworkInfoGrid
from app.models import FullReport, ModuleReport, NetworkInfo


@pytest.fixture(scope="module")
def qapp():
    app = QApplication.instance() or QApplication([])
    load_bundled_fonts()
    return app


def _report():
    results = [TestResult(f"tcp.h{i}.443", "tcp", status=S.OPEN, target=f"h{i}", port=443,
                          metadata={"role": "reachability", "target_is_ip": True}) for i in range(3)]
    results.append(TestResult("icmp.1", "icmp", status=S.TIMEOUT, target="1.1.1.1", error_code="TIMEOUT"))
    module = ModuleReport(module_name="TCP Port Scanner")
    for r in results:
        module.add(check_from_result(r.test_id, r))
    module.finish()
    info = NetworkInfo(internet_reachable=True, ipv4_available=True, ipv4_state="Available",
                       ipv6_state="Not configured")
    report = FullReport(network_info=info, modules=[module], generated_at=datetime.now())
    report.interpretations, report.summary = ResultAnalyzer().analyze_full(info, [module])
    return report


@pytest.mark.parametrize("lang", ["en", "fa"])
def test_diagnostics_tab_and_home_grid_render(qapp, lang):
    i18n.set_language(lang)
    from app.gui.tests_tab import DiagnosticsTab
    tab = DiagnosticsTab()
    tab.show_report(_report())
    texts = " ".join(label.text() for label in tab.findChildren(QLabel))
    assert ("یافته‌های کلیدی" if lang == "fa" else "Key findings") in texts
    grid = NetworkInfoGrid()
    grid.update_info(_report().network_info)
    assert grid.boxes["IPv6 Available"].value_widget.text() == ("پیکربندی نشده" if lang == "fa" else "Not configured")
    i18n.set_language("fa")
