"""DNS layers: configuration, server reachability, resolution outcomes, comparison, no timeout cascade."""
import socket

from app.core.dns_test import DNSTester, query_server
from app.diag.correlation import analyze
from app.diag.results import TechnicalStatus as S
from app.diag.testconfig import NetworkTestConfig, RetryPolicy

CFG = NetworkTestConfig(dns_timeout=0.2, retry=RetryPolicy(max_retries=0))
DOMAINS = ["a.example", "b.example", "c.example"]


def scripted(table):
    """query(server, domain, timeout) -> outcome tuple; table maps server -> outcome name or callable."""
    calls = []

    def q(server, domain, timeout):
        calls.append((server, domain))
        outcome = table[server]
        ips = ["93.184.216.34"] if outcome == "RESOLVED" else []
        return outcome, ips, 12.0, None, False
    q.calls = calls
    return q


def make_tester(table, system=None, tcp_ok=False, servers=("5.200.200.200",), resolvers=None):
    return DNSTester(CFG, domains=DOMAINS, resolvers=resolvers or {"Google": "8.8.8.8"},
                     configured_servers=list(servers), query=scripted(table),
                     tcp_check=lambda *a: tcp_ok,
                     system_lookup=system or (lambda d: ["93.184.216.34"]), include_doh=False)


def results_of(report, **filters):
    return [r for r in report.results if all(getattr(r, k, None) == v or r.metadata.get(k) == v
                                              for k, v in filters.items())]


def test_all_layers_succeed_and_are_reported_separately():
    rep = make_tester({"8.8.8.8": "RESOLVED", "5.200.200.200": "RESOLVED"}).run_all()
    cats = {r.category for r in rep.results}
    assert {"dns_config", "dns_server", "dns_resolution"} <= cats
    names = [c.name for c in rep.checks]
    assert "Local DNS Configuration" in names and "Resolve via Google (8.8.8.8)" in names
    assert "Resolve via Configured 5.200.200.200 (5.200.200.200)" in names
    assert all(c.status.value == "OK" for c in rep.checks)
    assert sum(1 for r in rep.results if r.category == "dns_resolution" and r.ok) == 9


def test_dns_timeout_is_timeout_not_nxdomain_and_does_not_cascade():
    q = scripted({"8.8.8.8": "TIMEOUT", "5.200.200.200": "RESOLVED"})
    t = DNSTester(CFG, domains=DOMAINS, resolvers={"Google": "8.8.8.8"}, configured_servers=[], query=q,
                  tcp_check=lambda *a: False, system_lookup=lambda d: ["1.1.1.1"], include_doh=False)
    rep = t.run_all()
    google = [r for r in rep.results if r.metadata.get("resolver") == "Google"]
    assert google[0].status is S.TIMEOUT and google[0].error_code == "TIMEOUT"
    assert [r.status for r in google[1:]] == [S.SKIPPED, S.SKIPPED]       # no 3 identical timeouts
    assert google[1].metadata["blocked_by"] == ["dns.server.Google"]
    assert len([c for c in q.calls if c[0] == "8.8.8.8"]) == 1
    srv = next(r for r in rep.results if r.test_id == "dns.server.Google")
    assert srv.status is S.TIMEOUT and srv.metrics["tcp_ok"] is False


def test_udp_blocked_but_tcp_dns_works_is_called_out():
    rep = make_tester({"8.8.8.8": "TIMEOUT", "5.200.200.200": "RESOLVED"}, tcp_ok=True).run_all()
    srv = next(r for r in rep.results if r.test_id == "dns.server.Google")
    assert srv.status is S.PARTIAL and srv.interpretation == "UDP_DNS_BLOCKED_TCP_WORKS"


def test_nxdomain_servfail_refused_are_distinct():
    for outcome, status in (("NXDOMAIN", S.DNS_FAILED), ("SERVFAIL", S.DNS_FAILED), ("REFUSED", S.REFUSED)):
        rep = make_tester({"8.8.8.8": outcome, "5.200.200.200": "RESOLVED"}).run_all()
        first = next(r for r in rep.results if r.metadata.get("resolver") == "Google" and r.category == "dns_resolution")
        assert first.status is status and first.error_code == outcome
        # the server *answered*, so it is reachable and the remaining domains are asked
        assert not any(r.skipped for r in rep.results if r.metadata.get("resolver") == "Google")


def test_system_resolver_failure_layer_is_reported_with_direct_resolvers_ok():
    def broken(domain):
        raise socket.gaierror(11001, "no such host")
    rep = make_tester({"8.8.8.8": "RESOLVED", "5.200.200.200": "RESOLVED"}, system=broken).run_all()
    sysres = [r for r in rep.results if r.metadata.get("role") == "system" and r.category == "dns_resolution"]
    assert len(sysres) == 3 and all(r.status is S.DNS_FAILED and r.error_code == "HOST_NOT_FOUND" for r in sysres)
    check = next(c for c in rep.checks if c.name.startswith("Resolve via system"))
    assert check.status.value == "FAILED" and check.result.interpretation == "SYSTEM_RESOLVER_FAILING"
    # the correlation engine turns that into one clear diagnosis
    summary = analyze(rep.results)
    d = next(d for d in summary.diagnoses if d.diagnosis_id == "dns_failure")
    assert "system" in d.title.lower() and "public resolvers answer" in d.title


def test_system_lookup_timeout_is_a_timeout():
    import time
    def slow(domain):
        time.sleep(1.5)
        return ["1.1.1.1"]
    t = DNSTester(NetworkTestConfig(dns_timeout=0.1), domains=["a.example"], resolvers={},
                  configured_servers=[], query=scripted({}), tcp_check=lambda *a: False,
                  system_lookup=slow, include_doh=False)
    srv, results, _ = t.probe_system()
    assert results[0].status is S.TIMEOUT and srv.status is S.DNS_FAILED


def test_single_failed_hostname_is_partial_not_total_failure():
    calls = {"n": 0}
    def flaky(domain):
        if domain == "b.example":
            raise socket.gaierror(socket.EAI_NONAME, "nx")
        return ["1.1.1.1"]
    rep = make_tester({"8.8.8.8": "RESOLVED", "5.200.200.200": "RESOLVED"}, system=flaky).run_all()
    check = next(c for c in rep.checks if c.name.startswith("Resolve via system"))
    assert check.status.value == "WARNING"
    assert "dns_failure" not in {d.diagnosis_id for d in analyze(rep.results).diagnoses}


def test_outlier_and_block_page_flags_reach_the_detailed_results():
    answers = {"Google": {d: ["142.250.1.1"] for d in DOMAINS},
               "Cloudflare": {d: ["142.250.1.1", "142.250.1.2"] for d in DOMAINS},
               "Quad9": {d: ["142.250.1.2"] for d in DOMAINS},
               "System": {d: ["93.184.216.34"] for d in DOMAINS}}
    t = make_tester({})
    cmp = t._compare_answers(answers)
    assert cmp.result.status is S.PARTIAL and cmp.result.confidence < 0.5
    assert set(cmp.details["outlier_resolvers"]) == set(DOMAINS)

    hijack = t._compare_answers({"System": {"a.example": ["10.10.34.34"]}, "Google": {"a.example": ["104.1.1.1"]}})
    assert hijack.result.status is S.BLOCKED and hijack.status.value == "FAILED"
    assert hijack.result.interpretation == "POSSIBLE_DNS_INTERFERENCE"


def test_query_server_maps_dns_rcodes(monkeypatch):
    import dns.flags, dns.message, dns.rcode, dns.rrset, dns.query
    def reply(rcode, answers=()):
        def fake(msg, server, timeout=None, **k):
            r = dns.message.make_response(msg); r.set_rcode(rcode)
            for a in answers:
                r.answer.append(dns.rrset.from_text(msg.question[0].name, 60, "IN", "A", a))
            return r, False
        return fake
    for rcode, want in ((dns.rcode.NXDOMAIN, "NXDOMAIN"), (dns.rcode.SERVFAIL, "SERVFAIL"), (dns.rcode.REFUSED, "REFUSED")):
        monkeypatch.setattr(dns.query, "udp_with_fallback", reply(rcode))
        assert query_server("9.9.9.9", "x.example", 1)[0] == want
    monkeypatch.setattr(dns.query, "udp_with_fallback", reply(dns.rcode.NOERROR, ["1.2.3.4"]))
    out = query_server("9.9.9.9", "x.example", 1)
    assert out[0] == "RESOLVED" and out[1] == ["1.2.3.4"]
    monkeypatch.setattr(dns.query, "udp_with_fallback", reply(dns.rcode.NOERROR))
    assert query_server("9.9.9.9", "x.example", 1)[0] == "NO_DATA"

    def timeout(*a, **k):
        raise dns.exception.Timeout()
    import dns.exception
    monkeypatch.setattr(dns.query, "udp_with_fallback", timeout)
    assert query_server("9.9.9.9", "x.example", 0.1)[0] == "TIMEOUT"
    monkeypatch.setattr(dns.query, "udp_with_fallback", lambda *a, **k: (_ for _ in ()).throw(OSError(10051, "net")))
    assert query_server("9.9.9.9", "x.example", 0.1)[0] == "NETWORK_ERROR"
