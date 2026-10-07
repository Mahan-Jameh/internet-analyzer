"""Layered website reachability: first failing layer, skipped downstream layers, control comparison."""
import ssl

import pytest

from app.core import site_reachability as sr
from app.diag.probes import Resolution
from app.diag.results import Severity, TechnicalStatus as S, TestResult


def _res(host, ips):
    return Resolution(host, ips[0] if ips else None, "IPv4" if ips else None, ips, 1.0,
                      None if ips else sr.normalize_wrapped_exception(OSError("x")))


def _tcp(status):
    def fake(host, port, cfg, **kw):
        r = TestResult(kw.get("test_id", "t"), "tcp", status=status, target=host, duration_ms=5.0,
                       error_code=None if status is S.OPEN else "TIMEOUT")
        r.summary = status.value
        return r
    return fake


def _tls(status, code=None):
    def fake(self, host, *a, **kw):
        r = TestResult(kw.get("test_id", "t"), "tls", status=status, target=host,
                       error_code=code, metrics={"handshake_ms": 9.0, "tls_version": "TLSv1.3"})
        return r
    return fake


@pytest.fixture
def tester():
    return sr.SiteReachabilityTester(["blocked.example"])


def test_dns_failure_skips_everything_after(monkeypatch, tester):
    monkeypatch.setattr(sr, "resolve", lambda h, f=None, port=0: _res(h, []))
    c = tester.check_site("blocked.example", False)
    assert c.details["failed_stage"] == "dns"
    assert c.details["layers"] == {"dns": "DNS_FAILED", "tcp": "SKIPPED", "tls": "SKIPPED", "http": "SKIPPED"}
    assert c.result.status is S.DNS_FAILED


def test_private_answer_is_possible_tampering_not_proof(monkeypatch, tester):
    monkeypatch.setattr(sr, "resolve", lambda h, f=None, port=0: _res(h, ["10.10.34.34"]))
    c = tester.check_site("blocked.example", False)
    assert c.result.interpretation == "POSSIBLE_DNS_TAMPERING"
    assert c.result.confidence < 0.8


def test_tcp_timeout_stops_before_tls(monkeypatch, tester):
    monkeypatch.setattr(sr, "resolve", lambda h, f=None, port=0: _res(h, ["93.184.216.34"]))
    monkeypatch.setattr(sr, "tcp_probe", _tcp(S.TIMEOUT))
    c = tester.check_site("blocked.example", False)
    assert c.details["failed_stage"] == "tcp"
    assert c.details["layers"]["tls"] == "SKIPPED"
    assert c.result.status is S.TIMEOUT        # raw status is kept, not rewritten as "blocked"


def test_tls_failure_after_tcp_ok(monkeypatch, tester):
    monkeypatch.setattr(sr, "resolve", lambda h, f=None, port=0: _res(h, ["93.184.216.34"]))
    monkeypatch.setattr(sr, "tcp_probe", _tcp(S.OPEN))
    monkeypatch.setattr(sr.TLSTester, "handshake_phases", _tls(S.RESET, "TLS_HANDSHAKE_RESET"))
    c = tester.check_site("blocked.example", False)
    assert c.details["failed_stage"] == "tls"
    assert c.details["layers"]["tcp"] == "OPEN"
    assert "not proof" in c.message


def test_success_all_layers(monkeypatch, tester):
    class Resp:
        status_code, http_version, is_redirect, headers = 200, "HTTP/2", False, {}
    monkeypatch.setattr(sr, "resolve", lambda h, f=None, port=0: _res(h, ["93.184.216.34"]))
    monkeypatch.setattr(sr, "tcp_probe", _tcp(S.OPEN))
    monkeypatch.setattr(sr.TLSTester, "handshake_phases", _tls(S.SUCCESS))
    monkeypatch.setattr(sr.httpx, "get", lambda *a, **k: Resp())
    c = tester.check_site("ok.example", True)
    assert c.details["failed_stage"] is None and c.result.severity is Severity.OK
    assert set(c.details["layers"].values()) == {"SUCCESS", "OPEN"} | {"SUCCESS"}


def test_http_451_is_blocked(monkeypatch, tester):
    class Resp:
        status_code, http_version, is_redirect, headers = 451, "HTTP/1.1", False, {}
    monkeypatch.setattr(sr, "resolve", lambda h, f=None, port=0: _res(h, ["93.184.216.34"]))
    monkeypatch.setattr(sr, "tcp_probe", _tcp(S.OPEN))
    monkeypatch.setattr(sr.TLSTester, "handshake_phases", _tls(S.SUCCESS))
    monkeypatch.setattr(sr.httpx, "get", lambda *a, **k: Resp())
    c = tester.check_site("blocked.example", False)
    assert c.result.status is S.BLOCKED and c.details["failed_stage"] == "http"


def test_crash_in_one_site_becomes_error_result(monkeypatch, tester):
    monkeypatch.setattr(sr, "resolve", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    c = tester._safe_check("x.example", False)
    assert c.result.status is S.ERROR


def test_run_all_collects_layer_results(monkeypatch):
    monkeypatch.setattr(sr, "resolve", lambda h, f=None, port=0: _res(h, []))
    report = sr.SiteReachabilityTester(["a.example"]).run_all()
    assert any(r.test_id.endswith(".dns") for r in report.results)
    assert report.checks[-1].name == "Control vs Test Comparison"
