
from app.core.compare import DEGRADED, IMPROVED, NEW, compare_reports
from app.core.environment_check import find_vpn_adapter_lines
from app.core.protocol_whitelist import interpret_outcomes
from app.core.site_reachability import SiteReachabilityTester, sanitize_hosts
from app.core.tcp_stall_test import classify_transfer
from app.core.worker import ALL_MODULES, DEFAULT_MODULES, MODULE_DISPLAY_NAMES, normalize_modules
from app.models import CheckResult, Status


# ---- TCP stall ---------------------------------------------------------
def test_stall_classification():
    assert classify_transfer(131072, 131072, True) == "complete"
    assert classify_transfer(5_000, 131072, False) == "stall_early"
    assert classify_transfer(17_000, 131072, False) == "stall_in_range"
    assert classify_transfer(90_000, 131072, False) == "stall_late"


# ---- site list handling ------------------------------------------------
def test_sanitize_hosts_cleans_and_filters():
    raw = ["https://Example.com/path", "example.com", "foo.org:443", "1.2.3.4",
           "not a host", "-bad.com", "", "ok-site.net"]
    assert sanitize_hosts(raw) == ["example.com", "foo.org", "ok-site.net"]


def test_sanitize_hosts_respects_limit():
    many = [f"site{i}.com" for i in range(50)]
    assert len(sanitize_hosts(many, limit=5)) == 5


def _site(host, control, status, stage=None):
    return CheckResult(name=host, status=status,
                       details={"control": control, "failed_stage": stage})


def test_control_vs_test_summary():
    tester = SiteReachabilityTester()
    ok = _site("c.com", True, Status.OK)
    failed = _site("t.com", False, Status.FAILED, "tls")
    assert tester._summarize([ok, failed]).status == Status.WARNING
    assert tester._summarize([ok, _site("t.com", False, Status.OK)]).status == Status.OK
    bad_control = _site("c.com", True, Status.FAILED, "dns")
    assert tester._summarize([bad_control, failed]).status == Status.FAILED


# ---- environment -------------------------------------------------------
def test_vpn_adapter_detection():
    text = """
Ethernet adapter Ethernet:
   Description . . . . . . . . . . . : Intel(R) Ethernet Connection
Unknown adapter Local Area Connection:
   Description . . . . . . . . . . . : Wintun Userspace Tunnel
Wireless LAN adapter Wi-Fi:
   Description . . . . . . . . . . . : Intel(R) Wi-Fi 6
"""
    found = find_vpn_adapter_lines(text)
    assert any("Wintun" in line for line in found)
    assert not any("Intel" in line for line in found)


# ---- protocol whitelist -------------------------------------------------
def test_protocol_whitelist_decision():
    assert interpret_outcomes("silent", "closed") == "filtered_suspected"
    assert interpret_outcomes("closed", "closed") == "no_difference"
    assert interpret_outcomes("silent", "silent") == "inconclusive"
    assert interpret_outcomes("connect_failed", "closed") == "unreachable"


# ---- worker module selection --------------------------------------------
def test_normalize_modules_always_starts_with_network_info_and_keeps_order():
    result = normalize_modules(["tls_test", "dns_test", "bogus"])
    assert result == ["network_info", "dns_test", "tls_test"]


def test_default_selection_excludes_opt_in_probe():
    assert "protocol_whitelist" in ALL_MODULES
    assert "protocol_whitelist" not in DEFAULT_MODULES
    assert set(ALL_MODULES) == set(MODULE_DISPLAY_NAMES)


# ---- comparison ---------------------------------------------------------
def _report(checks, ip="1.1.1.1"):
    return {"network_info": {"public_ip": ip, "ipv6_available": False},
            "modules": [{"module_name": "M", "checks": [
                {"name": n, "status": s, "message": n + s} for n, s in checks]}]}


def test_compare_reports_detects_changes():
    old = _report([("a", "OK"), ("b", "FAILED"), ("c", "OK")], ip="1.1.1.1")
    new = _report([("a", "WARNING"), ("b", "OK"), ("c", "OK"), ("d", "OK")], ip="2.2.2.2")
    result = compare_reports(old, new)
    changes = {d.check: d.change for d in result.check_diffs}
    assert changes == {"a": DEGRADED, "b": IMPROVED, "d": NEW}
    assert result.unchanged_count == 1
    assert [c.label for c in result.network_changes] == ["Public IP"]
