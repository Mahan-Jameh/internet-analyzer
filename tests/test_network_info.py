"""Layered IPv4/IPv6 detection and the auxiliary public-IP lookup."""
import requests

from app.core import network_info as N
from app.diag.localnet import LocalNetwork, RouteEntry, SourceAddress
from app.diag.neterrors import normalize_os_error
from app.diag.probes import Resolution
from app.diag.results import Severity, TechnicalStatus as S, TestResult
from app.diag.testconfig import NetworkTestConfig


def local(v4="192.168.1.50", v6=None, routes4=True, routes6=False):
    err = normalize_os_error(10051)
    return LocalNetwork(
        SourceAddress("IPv4", v4, None if v4 else err),
        SourceAddress("IPv6", v6, None if v6 else err),
        [RouteEntry("IPv4", "192.168.1.1", v4, 25)] if routes4 else [],
        [RouteEntry("IPv6", "fe80::1", "12", 281)] if routes6 else [],
        "Wi-Fi", ["8.8.8.8"])


def patch_probe(monkeypatch, ok_families):
    def fake(host, port, cfg, family=None, **kw):
        status = S.OPEN if family in ok_families else S.TIMEOUT
        return TestResult(f"tcp.{host}.{port}", "tcp", status=status, target=host, port=port,
                          error_code=None if status is S.OPEN else "TIMEOUT", duration_ms=10)
    monkeypatch.setattr(N, "tcp_probe", fake)
    monkeypatch.setattr(N, "resolve", lambda h, f=None, port=0: Resolution(h, "1.1.1.1", "IPv4", ["1.1.1.1"], 1.0))


def collector():
    return N.NetworkInfoCollector(NetworkTestConfig())


def test_ipv4_available_ipv6_not_configured(monkeypatch):
    patch_probe(monkeypatch, {"IPv4"})
    c = collector()
    v4 = c.check_ip_family("IPv4", local())
    v6 = c.check_ip_family("IPv6", local())
    assert v4.status is S.SUCCESS and v4.metrics["configured"] and v4.metrics["internet_connectivity"]
    assert v6.metrics["configured"] is False and v6.interpretation == "NOT_CONFIGURED"
    assert v6.severity is Severity.INFO          # missing IPv6 is normal, not a failure
    assert N._state_text(v6) == "Not configured" and N._state_text(v4) == "Available"


def test_ipv6_available(monkeypatch):
    patch_probe(monkeypatch, {"IPv4", "IPv6"})
    v6 = collector().check_ip_family("IPv6", local(v6="2001:db8::5", routes6=True))
    assert v6.ok and v6.metrics["configured"] and v6.metrics["default_route"]


def test_ipv6_configured_but_broken_is_warning_not_not_configured(monkeypatch):
    patch_probe(monkeypatch, {"IPv4"})
    v6 = collector().check_ip_family("IPv6", local(v6="2001:db8::5", routes6=True))
    assert v6.status is S.TIMEOUT and v6.severity is Severity.WARNING
    assert N._state_text(v6) == "Configured, but no Internet access"


def test_ipv4_unavailable_is_an_error_with_layers_preserved(monkeypatch):
    patch_probe(monkeypatch, set())
    v4 = collector().check_ip_family("IPv4", local(v4=None, routes4=False))
    assert not v4.ok and v4.severity is Severity.ERROR
    assert v4.metrics["configured"] is False and v4.metrics["internet_connectivity"] is False


def test_failed_getaddrinfo_alone_does_not_decide(monkeypatch):
    """DNS for this family failing must not mark IPv4 unavailable when TCP works."""
    patch_probe(monkeypatch, {"IPv4"})
    monkeypatch.setattr(N, "resolve", lambda h, f=None, port=0: Resolution(h, None, None, [], 1.0))
    v4 = collector().check_ip_family("IPv4", local())
    assert v4.ok and v4.metrics["dns_resolves"] is False


def test_collect_keeps_connectivity_separate_from_public_ip(monkeypatch):
    patch_probe(monkeypatch, {"IPv4"})
    monkeypatch.setattr(N, "collect_local_network", lambda: local())
    monkeypatch.setattr(N.requests, "get", lambda *a, **k: (_ for _ in ()).throw(requests.ConnectionError("x")))
    info = collector().collect()
    assert info.internet_reachable is True and info.public_ip is None
    assert info.public_ip_state == "LOOKUP_FAILED"
    pub = next(r for r in info.test_results if r.category == "public_ip")
    assert pub.severity is Severity.INFO and pub.status is S.INCONCLUSIVE
    assert info.ipv4_state == "Available" and info.ipv6_state == "Not configured"
    assert info.to_dict()["ip_layers"]["ipv4"]["configured"] is True


def test_public_ip_endpoints_are_compared(monkeypatch):
    class Resp:
        status_code = 200
        def __init__(self, data): self._d = data
        def json(self): return self._d
    answers = iter([Resp({"ip": "203.0.113.5", "org": "ISP", "country_name": "X", "city": "Y"}),
                    Resp({"query": "203.0.113.9", "isp": "ISP"})])
    monkeypatch.setattr(N.requests, "get", lambda *a, **k: next(answers))
    result, geo = collector().lookup_public_ip()
    assert result.metadata["state"] == "PUBLIC_IP_DETECTED" and geo["ip"] == "203.0.113.5"
    assert result.metrics["consistent"] is False and result.warnings
