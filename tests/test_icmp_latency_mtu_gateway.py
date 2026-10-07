"""ICMP semantics, latency statistics, MTU measurements, gateway diagnostics, basic HTTP/DNS normalization."""
import requests

from app.core import basic_connectivity as BC
from app.core.gateway import GatewayTester
from app.core.icmp import PingOutput, find_error_reporter, latency_stats, ping_result
from app.core.latency_test import LatencyTester
from app.core.mtu_test import MTUTester, parse_netsh_mtus
from app.core.vpn_connectivity import summarize
from app.diag.localnet import LocalNetwork, RouteEntry, SourceAddress
from app.diag.neterrors import normalize_wrapped_exception
from app.diag.probes import Resolution
from app.diag.results import Severity, TechnicalStatus as S, TestResult
from app.diag.testconfig import NetworkTestConfig

CFG = NetworkTestConfig(latency_probes=5)


def out(rtts=(), sent=4, hint=None, reporter=None, raw=""):
    return PingOutput(sent, list(rtts), 0, raw, hint, reporter, 5.0)


# ---- ICMP -------------------------------------------------------------------
def test_ping_success_and_partial_loss():
    ok = ping_result("1.1.1.1", 4, CFG, runner=lambda *a, **k: out([20, 22, 21, 23]))
    assert ok.status is S.SUCCESS and ok.interpretation == "ICMP_AVAILABLE"
    part = ping_result("1.1.1.1", 4, CFG, runner=lambda *a, **k: out([20, 22]))
    assert part.status is S.PARTIAL and part.metrics["packet_loss_percent"] == 50.0


def test_ping_silence_is_blocked_or_unavailable_never_internet_down():
    r = ping_result("1.1.1.1", 4, CFG, runner=lambda *a, **k: out())
    assert r.status is S.TIMEOUT and r.interpretation == "ICMP_BLOCKED_OR_UNAVAILABLE"
    assert r.severity is Severity.WARNING and "does not by itself mean" in r.summary


def test_ping_unreachable_reply_is_distinguished_from_silence():
    r = ping_result("8.8.8.8", 4, CFG, runner=lambda *a, **k: out(hint="HOST_UNREACHABLE", reporter="192.168.1.1"))
    assert r.status is S.UNREACHABLE and r.error_code == "HOST_UNREACHABLE" and "192.168.1.1" in r.summary
    n = ping_result("8.8.8.8", 4, CFG, runner=lambda *a, **k: out(hint="NETWORK_UNREACHABLE"))
    assert n.error_code == "NETWORK_UNREACHABLE"


def test_error_reporter_detection_is_language_independent():
    win = ("Pinging 8.8.8.8 with 32 bytes of data:\nReply from 192.168.1.1: Destination host unreachable.\n"
           "Ping statistics for 8.8.8.8:\n    Packets: Sent = 1, Received = 1, Lost = 0 (0% loss),")
    assert find_error_reporter(win, "8.8.8.8") == "192.168.1.1"
    assert find_error_reporter("Pinging one.one.one.one [1.1.1.1] with 32 bytes of data:\nRequest timed out.", "one.one.one.one") is None


def test_missing_ping_command_is_error_not_failure():
    r = ping_result("1.1.1.1", 4, CFG, runner=lambda *a, **k: out(hint="NO_PING_COMMAND"))
    assert r.status is S.ERROR and r.severity is Severity.INFO


# ---- latency statistics -------------------------------------------------------
def test_latency_stats_full_set():
    s = latency_stats([18, 20, 24, 47, 22], 5)
    assert s["packets_sent"] == 5 and s["packets_received"] == 5 and s["packet_loss_percent"] == 0
    assert (s["min_ms"], s["max_ms"], s["median_ms"]) == (18, 47, 22)
    assert s["jitter_ms"] == round((2 + 4 + 23 + 25) / 4, 1)


def test_latency_loss_and_no_replies():
    s = latency_stats([20.0] * 19, 20)
    assert s["packet_loss_percent"] == 5.0
    z = latency_stats([], 20)
    assert z["packet_loss_percent"] == 100.0 and z["average_ms"] is None


def test_latency_measure_icmp_and_tcp_fallback(monkeypatch):
    from app.core import latency_test as LT
    t = LatencyTester({"A": "1.1.1.1"}, config=CFG)
    monkeypatch.setattr(LT, "run_ping", lambda *a, **k: out([10, 12, 11, 10, 12], sent=5))
    r = t.measure("A", "1.1.1.1")
    assert r.status is S.SUCCESS and r.protocol == "ICMP" and r.metrics["measured_with"] == "ICMP"

    monkeypatch.setattr(LT, "run_ping", lambda *a, **k: out([], sent=5))
    monkeypatch.setattr(LT, "tcp_attempt", lambda ip, port, to: (None, 30.0, None))
    monkeypatch.setattr(LT, "TCP_SAMPLE_GAP_S", 0)
    r2 = t.measure("A", "1.1.1.1")
    assert r2.protocol == "TCP/443" and r2.status is S.SUCCESS and r2.warnings   # fallback is disclosed


def test_latency_high_loss_is_partial_with_warning(monkeypatch):
    from app.core import latency_test as LT
    monkeypatch.setattr(LT, "run_ping", lambda *a, **k: out([300, 310, 320], sent=5))
    r = LatencyTester({"A": "1.1.1.1"}, config=CFG).measure("A", "1.1.1.1")
    assert r.status is S.PARTIAL and r.severity is Severity.WARNING


def test_latency_nothing_answers(monkeypatch):
    from app.core import latency_test as LT
    monkeypatch.setattr(LT, "run_ping", lambda *a, **k: out([], sent=5))
    monkeypatch.setattr(LT, "resolve", lambda h, f=None, port=0: Resolution(h, "1.1.1.1", "IPv4", ["1.1.1.1"], 0))
    monkeypatch.setattr(LT, "tcp_attempt", lambda ip, port, to: (__import__("app.diag.neterrors", fromlist=["x"]).normalize_os_error(10060), 300.0, None))
    monkeypatch.setattr(LT, "TCP_SAMPLE_GAP_S", 0)
    r = LatencyTester({"A": "1.1.1.1"}, config=CFG).measure("A", "1.1.1.1")
    assert r.status is S.TIMEOUT and r.metrics["packet_loss_percent"] == 100.0


# ---- MTU ------------------------------------------------------------------------
def fake_mtu_runner(path_mtu, reporter=None):
    def run(host, count, timeout, family=None, df_size=None, interval_s=None):
        ok = df_size is not None and df_size + 28 <= path_mtu
        return PingOutput(1, [10.0] if ok else [], 0, "", None, None if ok else reporter, 1.0)
    return run


def test_mtu_standard_path():
    r = MTUTester(runner=fake_mtu_runner(1500)).measure()
    assert r.status is S.SUCCESS and r.metrics["discovered_path_mtu"] == 1500
    assert r.metrics["pmtud_status"] == "not_needed"


def test_mtu_reduced_reports_measurements_and_cautious_wording():
    r = MTUTester(runner=fake_mtu_runner(1420)).measure()
    m = r.metrics
    assert m["discovered_path_mtu"] == 1420 and m["largest_successful_packet"] == 1420
    assert m["smallest_failed_packet"] == 1421 and m["largest_failed_packet"] == 1500
    assert m["pmtud_status"] == "no_icmp_feedback" and r.warnings
    assert "Possible" in r.summary and r.interpretation == "REDUCED_PATH_MTU" and r.confidence < 0.5


def test_mtu_pmtud_working_when_router_answers():
    r = MTUTester(runner=fake_mtu_runner(1400, reporter="10.0.0.1")).measure()
    assert r.metrics["pmtud_status"] == "working" and not r.warnings


def test_mtu_icmp_blocked_is_inconclusive():
    r = MTUTester(runner=lambda *a, **k: PingOutput(1, [], 0, "", None, None, 1.0)).measure()
    assert r.status is S.INCONCLUSIVE and r.interpretation == "ICMP_BLOCKED_OR_UNAVAILABLE"


def test_netsh_mtu_parsing_is_numeric():
    text = "   MTU  MeanBytesIn  MeanBytesOut  Interface\n------\n  1500   1000   2000   4000   Wi-Fi\n4294967295 0 0 0 Loopback Pseudo-Interface 1"
    assert parse_netsh_mtus(text) == {"Wi-Fi": 1500}


# ---- gateway ------------------------------------------------------------------------
def local_net(gw="192.168.1.1", usable=True):
    return LocalNetwork(SourceAddress("IPv4", "192.168.1.5" if usable else None), SourceAddress("IPv6", None),
                        [RouteEntry("IPv4", gw, "192.168.1.5", 25)] if (gw or usable) else [], [], "Wi-Fi", [])


def icmp_stub(status):
    return lambda host, count, cfg, **kw: TestResult("icmp.gw", "icmp", status=status, metrics={"average_ms": 2, "packets_received": 3})


def tcp_stub(status):
    return lambda host, port, cfg, **kw: TestResult(f"tcp.{host}.{port}", "tcp", status=status, port=port)


def test_gateway_reachable_by_ping():
    g = GatewayTester(local=local_net(), ping=icmp_stub(S.SUCCESS), tcp=tcp_stub(S.TIMEOUT), config=CFG)
    assert g.check_gateway(local_net()).status is S.SUCCESS


def test_gateway_ignoring_ping_but_refusing_tcp_is_alive():
    g = GatewayTester(ping=icmp_stub(S.TIMEOUT), tcp=tcp_stub(S.CLOSED), config=CFG)
    r = g.check_gateway(local_net())
    assert r.status is S.SUCCESS and r.warnings and "ICMP" in r.warnings[0]


def test_gateway_silent_is_hint_only():
    g = GatewayTester(ping=icmp_stub(S.TIMEOUT), tcp=tcp_stub(S.TIMEOUT), config=CFG)
    r = g.check_gateway(local_net())
    assert r.status is S.TIMEOUT and r.severity is Severity.WARNING and r.confidence == 0.5


def test_no_default_route_and_onlink_vpn_route():
    g = GatewayTester(config=CFG)
    none = g.check_gateway(LocalNetwork(SourceAddress("IPv4", None), SourceAddress("IPv6", None)))
    assert none.error_code == "NO_DEFAULT_ROUTE" and none.severity is Severity.ERROR
    onlink = g.check_gateway(local_net(gw=None))
    assert onlink.status is S.NOT_APPLICABLE


def test_local_interface_down():
    g = GatewayTester(config=CFG)
    r = g.check_interface(LocalNetwork(SourceAddress("IPv4", None), SourceAddress("IPv6", None)))
    assert r.status is S.UNREACHABLE and r.severity is Severity.CRITICAL
    assert g.check_interface(local_net()).status is S.SUCCESS


# ---- VPN reading ------------------------------------------------------------------------
def test_vpn_summary_never_concludes_blocking_from_silence():
    tcp = [TestResult("t", "tcp", status=S.TIMEOUT, port=443)]
    udp = [TestResult("u", "udp", status=S.INCONCLUSIVE, port=51820)]
    r = summarize(tcp, udp)
    assert r.interpretation == "NO_CONCLUSION" and r.confidence <= 0.3 and "not enough" in r.summary
    ok = summarize([TestResult("t", "tcp", status=S.OPEN, port=443)], udp)
    assert ok.interpretation == "SOME_TRANSPORTS_REACHABLE"


# ---- basic connectivity: HTTP / DNS normalization --------------------------------------
class _Resp:
    def __init__(self, code, url="https://x/"):
        self.status_code, self.url = code, url


def _tester():
    return BC.BasicConnectivityTester(config=CFG)


def test_http_success_and_unexpected_status(monkeypatch):
    monkeypatch.setattr(BC.requests, "get", lambda *a, **k: _Resp(200))
    assert _tester().http_request("https://x/").result.status is S.SUCCESS
    monkeypatch.setattr(BC.requests, "get", lambda *a, **k: _Resp(503))
    r = _tester().http_request("https://x/").result
    assert r.status is S.HTTP_FAILED and r.error_code == "HTTP_503" and r.severity is Severity.WARNING
    monkeypatch.setattr(BC.requests, "get", lambda *a, **k: _Resp(451))
    assert _tester().http_request("https://x/").result.status is S.BLOCKED


def test_http_timeout_is_timeout(monkeypatch):
    def boom(*a, **k): raise requests.exceptions.ConnectTimeout("timed out")
    monkeypatch.setattr(BC.requests, "get", boom)
    c = _tester().http_request("https://x/")
    assert c.result.status is S.TIMEOUT and c.status.value == "WARNING"


def test_http_wrapped_errors_are_classified_by_their_cause(monkeypatch):
    import socket as sk, ssl
    cases = [
        (requests.exceptions.ConnectionError(sk.gaierror(11001, "no host")), S.DNS_FAILED, "HOST_NOT_FOUND"),
        (requests.exceptions.ConnectionError(ConnectionRefusedError(111, "refused")), S.HTTP_FAILED, "CONNECTION_REFUSED"),
        (requests.exceptions.SSLError(ssl.SSLCertVerificationError(1, "bad")), S.TLS_FAILED, "CERTIFICATE_ERROR"),
    ]
    for exc, status, code in cases:
        monkeypatch.setattr(BC.requests, "get", lambda *a, e=exc, **k: (_ for _ in ()).throw(e))
        r = _tester().http_request("https://x/").result
        assert (r.status, r.error_code) == (status, code), (exc, r.status, r.error_code)


def test_wrapped_exception_text_fallback():
    n = normalize_wrapped_exception(requests.exceptions.SSLError("[SSL: CERTIFICATE_VERIFY_FAILED] bad"))
    assert n.error_code == "CERTIFICATE_ERROR"


def test_dns_resolution_success_and_failure(monkeypatch):
    monkeypatch.setattr(BC, "resolve", lambda h, *a, **k: Resolution(h, "1.2.3.4", "IPv4", ["1.2.3.4"], 3.0))
    ok = _tester().dns_resolution("a.com")
    assert ok.result.status is S.SUCCESS and ok.result.metadata["role"] == "system"
    from app.diag.neterrors import normalize_os_error
    monkeypatch.setattr(BC, "resolve", lambda h, *a, **k: Resolution(h, None, None, [], 3.0, normalize_os_error(11001)))
    bad = _tester().dns_resolution("a.com")
    assert bad.result.status is S.DNS_FAILED and bad.status.value == "FAILED"
