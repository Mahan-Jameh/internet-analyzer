"""Protocol tests, stall test and whitelist emit normalized TestResults."""
import socket

from app.core import protocol_tests as pt
from app.core.protocol_whitelist import ProtocolWhitelistProbe
from app.core.tcp_stall_test import TCPStallTester
from app.diag.results import Severity, TechnicalStatus as S, TestResult


class FakeSock:
    def __init__(self, behaviour):
        self.behaviour = behaviour
    def __enter__(self): return self
    def __exit__(self, *a): return False
    def settimeout(self, t): pass
    def connect(self, a): pass
    def send(self, d): pass
    def recv(self, n):
        raise self.behaviour


def _quic(monkeypatch, exc):
    monkeypatch.setattr(pt.socket, "socket", lambda *a, **k: FakeSock(exc))
    return pt.ProtocolTester()._quic_reachability()


def test_quic_silence_is_inconclusive_not_failure(monkeypatch):
    c = _quic(monkeypatch, socket.timeout())
    assert c.result.status is S.OPEN_OR_FILTERED and c.result.severity is Severity.INFO


def test_quic_icmp_unreachable_is_closed(monkeypatch):
    c = _quic(monkeypatch, ConnectionResetError(10054, "reset"))
    assert c.result.status is S.CLOSED and c.result.platform_error == 10054


def test_icmp_silence_is_info_and_hedged(monkeypatch):
    from app.core.icmp import PingOutput
    monkeypatch.setattr(pt, "ping_result", lambda host, count, cfg, **kw: __import__("app.core.icmp", fromlist=["x"]).ping_result(
        host, count, cfg, runner=lambda h, c, t, family=None: PingOutput(sent=2, rtts=[], code=1, raw="Request timed out.", duration_ms=1.0), **kw))
    c = pt.ProtocolTester()._icmp()
    assert c.result.status is S.TIMEOUT and c.result.severity is Severity.INFO
    assert "does not by itself mean" in c.result.summary


def test_doh_http_error_is_normalized(monkeypatch):
    import httpx
    def boom(*a, **k): raise httpx.ConnectTimeout("t")
    monkeypatch.setattr(pt.httpx, "get", boom)
    c = pt.ProtocolTester()._doh("X", "https://x.example/dns")
    assert c.result.status is S.TIMEOUT and c.result.error_code == "TIMEOUT"


def test_one_crashing_step_does_not_break_module(monkeypatch):
    t = pt.ProtocolTester()
    monkeypatch.setattr(t, "_quic_reachability", lambda: (_ for _ in ()).throw(RuntimeError("x")))
    monkeypatch.setattr(t, "_doh", lambda n, e: t._icmp.__self__._icmp() if False else (_ for _ in ()).throw(RuntimeError("y")))
    monkeypatch.setattr(t, "_dot", lambda n, s: (_ for _ in ()).throw(RuntimeError("z")))
    monkeypatch.setattr(t, "_icmp", lambda: (_ for _ in ()).throw(RuntimeError("i")))
    monkeypatch.setattr(t, "_websocket", lambda: (_ for _ in ()).throw(RuntimeError("w")))
    report = t.run_all()
    assert report.results and all(r.status is S.ERROR for r in report.results)


def test_stall_result_complete_and_stall(monkeypatch):
    t = TCPStallTester()
    monkeypatch.setattr(t, "_download", lambda size: (size, True, ""))
    c = t._run_check()
    assert c.result.status is S.SUCCESS
    calls = iter([(10, True, ""), (18000, False, "ReadError: reset")])
    monkeypatch.setattr(t, "_download", lambda size: next(calls))
    c = t._run_check()
    assert c.result.interpretation == "STALL_IN_SUSPECT_RANGE" and c.result.confidence <= 0.6
    monkeypatch.setattr(t, "_download", lambda size: (0, False, "timeout"))
    c = t._run_check()
    assert c.result.status is S.INCONCLUSIVE        # control failed -> no verdict


def test_whitelist_result_mapping(monkeypatch):
    p = ProtocolWhitelistProbe()
    monkeypatch.setattr("app.core.protocol_whitelist.resolve_host", lambda *a, **k: ["1.2.3.4"])
    monkeypatch.setattr(p, "_baseline_tls_ok", lambda ip: True)
    outcomes = iter(["reset", "silent"])          # control, monitored
    monkeypatch.setattr(p, "_send_payload", lambda ip, port: next(outcomes))
    c = p._run_check()
    assert c.result.interpretation == "POSSIBLE_PROTOCOL_WHITELIST" and c.result.confidence <= 0.5
