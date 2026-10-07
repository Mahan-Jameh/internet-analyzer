import csv
import io
import json
from datetime import datetime, timedelta

from app.core.analyzer import ResultAnalyzer
from app.export.exporter import to_csv, to_html, to_json, to_txt
from app.export.history import list_history, load_report, save_to_history
from app.models import CheckResult, FullReport, ModuleReport, NetworkInfo, Status

FORBIDDEN = ("definitely", "certainly", "proves that", "is censoring", "guaranteed")


def _info():
    return NetworkInfo(public_ip="1.2.3.4", isp="Test ISP", ipv4_available=True,
                       internet_reachable=True, dns_servers=["1.1.1.1"])


def _module(name, *checks):
    module = ModuleReport(module_name=name)
    for check in checks:
        module.add(check)
    module.finish()
    return module


def _full_report(when=None, message="ok"):
    module = _module("DNS Test", CheckResult("Resolve via X", Status.OK, message))
    return FullReport(network_info=_info(), modules=[module],
                      generated_at=when or datetime.now(), duration_seconds=3.2)


# ---- history ---------------------------------------------------------------
def test_history_roundtrip_and_ordering(tmp_path):
    now = datetime.now()
    first = save_to_history(_full_report(now - timedelta(hours=1)), tmp_path)
    second = save_to_history(_full_report(now), tmp_path)
    entries = list_history(tmp_path)
    assert [e.path for e in entries] == [second, first]          # newest first
    assert load_report(first)["modules"][0]["module_name"] == "DNS Test"


def test_history_skips_corrupt_files(tmp_path):
    save_to_history(_full_report(), tmp_path)
    (tmp_path / "run_broken.json").write_text("{not json", encoding="utf-8")
    assert len(list_history(tmp_path)) == 1


# ---- analyzer ---------------------------------------------------------------
def test_analyzer_flags_sni_stall_and_environment_with_hedged_language():
    tls = _module("TLS Test", CheckResult(
        "SNI Filtering Probe", Status.WARNING, "x", details={"suspected": True}))
    stall = _module("TCP Stall Test", CheckResult(
        "TCP Stall (16-20 KB) Test", Status.WARNING, "x", details={"suspected": True}))
    env = _module("Proxy & VPN Detection", CheckResult(
        "System Proxy Settings", Status.WARNING, "x", details={"suspected": True}))
    texts = [i.text for i in ResultAnalyzer().analyze(_info(), [tls, stall, env])]
    joined = " ".join(texts)

    assert "SNI-based filtering" in joined
    assert "10-40 KB" in joined
    assert "proxy or VPN" in joined
    assert not any(word in joined.lower() for word in FORBIDDEN)


def test_analyzer_reports_what_works():
    dns = _module("DNS Test", CheckResult("Resolve via Google (8.8.8.8)", Status.OK, "ok"))
    texts = [i.text for i in ResultAnalyzer().analyze(_info(), [dns])]
    assert any("DNS resolution is working" in t for t in texts)


# ---- exporters ----------------------------------------------------------------
def test_html_export_escapes_untrusted_text():
    report = _full_report(message="<script>alert(1)</script>")
    report.network_info.isp = "<img src=x onerror=alert(1)>"
    html_text = to_html(report)
    assert "<script>alert(1)" not in html_text
    assert "<img src=x" not in html_text
    assert "&lt;script&gt;" in html_text


def test_csv_export_neutralises_formulas():
    report = _full_report(message="=HYPERLINK(\"http://evil\")")
    rows = list(csv.reader(io.StringIO(to_csv(report))))
    assert rows[1][3].startswith("'=")


def test_json_and_txt_exports_contain_new_fields():
    report = _full_report()
    data = json.loads(to_json(report))
    assert data["duration_seconds"] == 3.2 and data["cancelled"] is False
    assert "DNS Test" in to_txt(report)


# ---- schema v2 / four layers -------------------------------------------------
def _rich_report():
    from app.diag.adapter import check_from_result
    from app.diag.results import TechnicalStatus as S, TestResult
    t = TestResult("tcp.example.com.443", "tcp", status=S.TIMEOUT, target="example.com", port=443,
                   error_code="TIMEOUT", interpretation="FILTERED_OR_UNREACHABLE", confidence=0.4,
                   metadata={"role": "reachability"})
    module = ModuleReport(module_name="TCP Port Scanner")
    module.add(check_from_result("TCP 443 (HTTPS)", t))
    module.finish()
    report = FullReport(network_info=_info(), modules=[module], generated_at=datetime.now())
    report.interpretations, report.summary = ResultAnalyzer().analyze_full(report.network_info, [module])
    return report


def test_json_is_schema_v2_and_keeps_v1_keys():
    data = json.loads(to_json(_rich_report()))
    assert data["schema_version"] == 2
    for key in ("run", "tests", "diagnoses", "summary", "key_findings", "modules", "interpretations",
                "network_info", "generated_at"):
        assert key in data
    assert data["tests"][0]["status"] == "TIMEOUT" and data["tests"][0]["error_code"] == "TIMEOUT"
    assert data["network_info"]["ipv4_state"] == "Unknown"


def test_v1_history_file_still_loads(tmp_path):
    old = {"generated_at": "2025-01-01T10:00:00", "profile_name": None, "duration_seconds": 5,
           "cancelled": False, "target_host": None, "network_info": {"public_ip": "1.1.1.1"},
           "modules": [{"module_name": "DNS Test", "overall_status": "OK", "checks": []}],
           "interpretations": []}
    (tmp_path / "run_20250101_100000_000000.json").write_text(json.dumps(old), encoding="utf-8")
    entries = list_history(tmp_path)
    assert len(entries) == 1
    data = load_report(entries[0].path)
    assert data["schema_version"] == 1 and data["tests"] == [] and data["diagnoses"] == []
    assert data["run"]["generated_at"] == "2025-01-01T10:00:00"


def test_compare_v1_with_v2_reports_does_not_invent_network_changes():
    from app.core.compare import compare_reports
    from app.export.history import normalize_report_dict
    old = normalize_report_dict({"modules": [], "network_info": {"public_ip": "1.1.1.1"}})
    new = json.loads(to_json(_rich_report()))
    result = compare_reports(old, new)
    assert all(c.label not in ("IPv4", "IPv6", "Public IP lookup") for c in result.network_changes)


def test_txt_and_html_show_all_four_layers_and_hedged_root_cause():
    report = _rich_report()
    txt = to_txt(report, "en")
    for heading in ("1. Overall summary", "2. Key findings", "3. Technical evidence", "4. Root cause analysis"):
        assert heading in txt
    assert "[TIMEOUT | code=TIMEOUT" in txt                      # raw observation line
    assert not any(w in txt.lower() for w in FORBIDDEN)
    html_text = to_html(report, "en")
    assert "Technical evidence" in html_text and "Root cause analysis" in html_text


def test_csv_has_technical_columns():
    rows = list(csv.reader(io.StringIO(to_csv(_rich_report()))))
    assert rows[0][-6:] == ["Technical Status", "Severity", "Error Code", "OS Error", "Interpretation", "Confidence"]
    assert rows[1][6] == "TIMEOUT" and rows[1][8] == "TIMEOUT"


def test_persian_txt_export_has_persian_layer_headings():
    txt = to_txt(_rich_report(), "fa")
    assert "خلاصه‌ی کلی" in txt and "یافته‌های کلیدی" in txt and "شواهد فنی" in txt
