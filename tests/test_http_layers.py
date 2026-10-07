"""HTTP as layers: DNS -> TCP -> TLS -> request, with dependency skipping and classified errors."""
import httpx
import pytest

from app.core import http_test as H
from app.core.http_test import HTTPTester, block_page_reasons
from app.diag.neterrors import normalize_os_error
from app.diag.probes import Resolution
from app.diag.results import Severity, TechnicalStatus as S, TestResult
from app.diag.testconfig import NetworkTestConfig, RetryPolicy

CFG = NetworkTestConfig(connect_timeout=0.2, read_timeout=0.5, retry=RetryPolicy(max_retries=0))
RES_OK = Resolution("www.cloudflare.com", "104.16.1.1", "IPv4", ["104.16.1.1"], 2.0)


class Resp:
    def __init__(self, code=200, headers=None, url="https://www.cloudflare.com/", text="", version="HTTP/2", history=()):
        self.status_code, self.url, self.text = code, url, text
        self.headers = {"cf-ray": "abc", "alt-svc": 'h3=":443"', **(headers or {})}
        self.http_version, self.history = version, list(history)
        self.is_redirect = 300 <= code < 400


def layered(monkeypatch, dns=True, tcp=S.OPEN, tls=S.SUCCESS):
    if dns:
        monkeypatch.setattr(H, "resolve", lambda h, f=None, port=0: RES_OK)
    else:
        monkeypatch.setattr(H, "resolve", lambda h, f=None, port=0: Resolution(h, None, None, [], 1.0, normalize_os_error(11001)))
    monkeypatch.setattr(H, "tcp_probe", lambda host, port, cfg, **kw: TestResult(kw.get("test_id", "t"), "tcp", status=tcp, port=port))
    monkeypatch.setattr(HTTPTester, "_tls_layer", lambda self, ip: TestResult("tls", "tls", status=tls, metadata={"role": "handshake"}))


def fake_http(monkeypatch, get=None):
    monkeypatch.setattr(H.httpx, "get", get or (lambda url, **k: Resp(200)))

    class Client:
        def __init__(self, **k): pass
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def get(self, url): return Resp(200)
    monkeypatch.setattr(H.httpx, "Client", Client)
    monkeypatch.setattr(HTTPTester, "_connection_reuse", lambda self: __import__("app.diag.adapter", fromlist=["x"]).check_from_result(
        "Connection Reuse (Keep-Alive)", TestResult("http.keepalive", "http", status=S.SUCCESS, metadata={"role": "keepalive"})))
    monkeypatch.setattr(HTTPTester, "_http3_hint", lambda self: __import__("app.diag.adapter", fromlist=["x"]).check_from_result(
        "HTTP/3 (QUIC) Support", TestResult("http.http3", "http", status=S.SUCCESS, metadata={"role": "http3"})))


def by_name(report):
    return {c.name: c for c in report.checks}


def test_all_layers_ok_gives_one_result_per_layer(monkeypatch):
    layered(monkeypatch); fake_http(monkeypatch)
    rep = HTTPTester(config=CFG).run_all()
    c = by_name(rep)
    for layer in ("HTTP Layer: DNS", "HTTP Layer: TCP 443", "HTTP Layer: TLS", "Plain HTTP", "HTTPS",
                  "HTTP/2 Support", "HTTP Redirect", "Response Compression"):
        assert c[layer].status.value in ("OK", "WARNING"), layer
    assert c["HTTP Layer: DNS"].status.value == "OK" and c["HTTPS"].result.status is S.SUCCESS


def test_dns_failure_blocks_every_dependent_layer_without_fake_failures(monkeypatch):
    layered(monkeypatch, dns=False); fake_http(monkeypatch)
    rep = HTTPTester(config=CFG).run_all()
    c = by_name(rep)
    assert c["HTTP Layer: DNS"].result.status is S.DNS_FAILED
    for name in ("HTTP Layer: TCP 443", "HTTP Layer: TLS", "HTTPS", "HTTP/2 Support", "HTTP/3 (QUIC) Support",
                 "Plain HTTP", "HTTP Redirect", "Response Compression", "Connection Reuse (Keep-Alive)"):
        r = c[name].result
        assert r.status is S.SKIPPED and r.metadata["skip_reason"] == "BLOCKED_BY_DEPENDENCY", name
        assert c[name].status.value == "UNKNOWN"
    assert sum(1 for x in c.values() if x.status.value == "FAILED") == 1     # only the DNS layer failed


def test_tcp_failure_blocks_tls_and_https_but_not_dns_only_steps(monkeypatch):
    layered(monkeypatch, tcp=S.TIMEOUT); fake_http(monkeypatch)
    c = by_name(HTTPTester(config=CFG).run_all())
    assert c["HTTP Layer: TCP 443"].result.status is S.TIMEOUT
    assert c["HTTP Layer: TLS"].result.metadata["blocked_by"] == ["http.layer.tcp"]
    assert c["HTTPS"].result.status is S.SKIPPED and c["HTTP/2 Support"].result.status is S.SKIPPED
    assert c["Plain HTTP"].result.status is S.SUCCESS            # port 80 does not depend on TCP/443


def test_tls_failure_skips_http_layers_and_is_reported_as_tls(monkeypatch):
    layered(monkeypatch, tls=S.TLS_FAILED); fake_http(monkeypatch)
    c = by_name(HTTPTester(config=CFG).run_all())
    assert c["HTTP Layer: TLS"].result.status is S.TLS_FAILED
    assert c["HTTPS"].result.status is S.SKIPPED and c["HTTPS"].result.metadata["blocked_by"] == ["http.layer.tls"]


def test_http_timeout_and_status_errors_are_classified(monkeypatch):
    layered(monkeypatch)
    def get(url, **k):
        if url == H.HTTP_TEST_URL_TLS:
            raise httpx.ReadTimeout("slow")
        return Resp(503)
    fake_http(monkeypatch, get)
    c = by_name(HTTPTester(config=CFG).run_all())
    assert c["HTTPS"].result.status is S.TIMEOUT and c["HTTPS"].result.error_code == "TIMEOUT"
    assert c["Plain HTTP"].result.status is S.HTTP_FAILED and c["Plain HTTP"].result.error_code == "HTTP_503"
    assert c["Plain HTTP"].status.value == "WARNING"


def test_http2_falling_back_to_http11_is_partial(monkeypatch):
    layered(monkeypatch); fake_http(monkeypatch)
    class Client:
        def __init__(self, **k): pass
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def get(self, url): return Resp(200, version="HTTP/1.1")
    monkeypatch.setattr(H.httpx, "Client", Client)
    r = by_name(HTTPTester(config=CFG).run_all())["HTTP/2 Support"].result
    assert r.status is S.PARTIAL and r.severity is Severity.WARNING and r.metrics["http_version"] == "HTTP/1.1"


def test_http3_failure_is_only_a_warning_never_a_diagnosis_of_https_failure(monkeypatch):
    from app.diag.correlation import analyze
    layered(monkeypatch, tcp=S.OPEN, tls=S.SUCCESS); fake_http(monkeypatch)
    from app.diag.adapter import check_from_result
    monkeypatch.setattr(HTTPTester, "_http3_hint", lambda self: check_from_result(
        "HTTP/3 (QUIC) Support", TestResult("http.http3", "http", status=S.HTTP_FAILED, severity=Severity.WARNING,
                                            metadata={"role": "http3"})))
    rep = HTTPTester(config=CFG).run_all()
    assert by_name(rep)["HTTP/3 (QUIC) Support"].status.value == "WARNING"
    assert "tls_failure" not in {d.diagnosis_id for d in analyze(rep.results).diagnoses}


def test_missing_expected_headers_flag_possible_content_mismatch(monkeypatch):
    layered(monkeypatch)
    fake_http(monkeypatch, lambda url, **k: Resp(200, headers={}) if "cloudflare.com" in url else Resp(200))
    resp = Resp(200); resp.headers = {}
    monkeypatch.setattr(H.httpx, "get", lambda url, **k: resp)
    r = by_name(HTTPTester(config=CFG).run_all())["HTTPS"].result
    assert r.status is S.PARTIAL and r.interpretation == "CONTENT_MISMATCH_POSSIBLE" and r.confidence <= 0.5


def test_proxy_headers_on_an_error_are_recorded_as_evidence(monkeypatch):
    layered(monkeypatch)
    fake_http(monkeypatch, lambda url, **k: Resp(502, headers={"via": "1.1 squid"}))
    r = by_name(HTTPTester(config=CFG).run_all())["HTTPS"].result
    assert r.interpretation == "PROXY_GENERATED_RESPONSE_POSSIBLE" and r.metadata["proxy_headers"] == {"via": "1.1 squid"}


def test_block_page_reasons_pure_function():
    assert block_page_reasons(451, "", False, "") == ["HTTP 451 (unavailable for legal reasons)"]
    assert "private address" in block_page_reasons(302, "http://10.10.34.34/", True, "")[0]
    assert "iframe" in block_page_reasons(200, "", False, '<iframe src="http://192.168.1.1/x">')[0]
    assert block_page_reasons(200, "", False, "<html>hello</html>") == []


def test_block_page_check_result(monkeypatch):
    layered(monkeypatch)
    fake_http(monkeypatch, lambda url, **k: Resp(302, headers={"location": "http://10.10.34.34/"}, url=url))
    c = by_name(HTTPTester(config=CFG).run_all())["Block Page Detection"]
    assert c.result.status is S.BLOCKED and c.status.value == "FAILED" and c.details["suspected"] is True
    assert c.result.interpretation == "POSSIBLE_BLOCK_PAGE" and c.result.confidence < 0.9


def test_http_success_has_no_error_fields(monkeypatch):
    layered(monkeypatch); fake_http(monkeypatch)
    r = by_name(HTTPTester(config=CFG).run_all())["HTTPS"].result
    assert r.status is S.SUCCESS and r.error_code is None and r.metrics["status_code"] == 200
