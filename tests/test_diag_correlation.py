"""Root-cause engine: each of the cases A-F from the spec plus anti-overclaiming checks."""
from app.diag.correlation import OverallStatus, analyze
from app.diag.results import RetryOutcome, Severity, TechnicalStatus as S, TestResult


def R(tid, cat, status, **kw):
    meta = kw.pop("meta", {})
    return TestResult(tid, cat, status=status, metadata=meta, **kw)


def tcp(host, port, status, ip=False, **kw):
    return R(f"tcp.{host}.{port}", "tcp", status, target=host, port=port, meta={"target_is_ip": ip}, **kw)


def ids(summary):
    return {d.diagnosis_id for d in summary.diagnoses}


def test_case_a_dns_failed_but_ip_ok():
    results = [
        R("gateway", "gateway", S.SUCCESS),
        tcp("1.1.1.1", 443, S.OPEN, ip=True),
        R("dns.sys.a", "dns_resolution", S.DNS_FAILED, target="a.com", meta={"role": "system", "domain": "a.com"}),
        R("dns.sys.b", "dns_resolution", S.DNS_FAILED, target="b.com", meta={"role": "system", "domain": "b.com"}),
        R("dns.d.a", "dns_resolution", S.SUCCESS, target="a.com", meta={"role": "direct", "domain": "a.com"}),
    ]
    s = analyze(results)
    d = next(d for d in s.diagnoses if d.diagnosis_id == "dns_failure")
    assert "system" in d.title.lower() and d.confidence >= 0.8
    assert d.wording == "Likely"


def test_single_failed_hostname_is_not_a_dns_diagnosis():
    results = [
        R("dns.sys.a", "dns_resolution", S.DNS_FAILED, target="a.com", meta={"role": "system", "domain": "a.com"}),
        R("dns.sys.b", "dns_resolution", S.SUCCESS, target="b.com", meta={"role": "system", "domain": "b.com"}),
    ]
    assert "dns_failure" not in ids(analyze(results))


def test_case_b_tcp_failing_with_icmp_ok():
    results = [
        R("dns.ok", "dns_resolution", S.SUCCESS, meta={"role": "system"}),
        tcp("example.com", 443, S.TIMEOUT), tcp("example.com", 80, S.TIMEOUT),
        R("icmp.1", "icmp", S.SUCCESS),
    ]
    d = next(d for d in analyze(results).diagnoses if d.diagnosis_id == "tcp_filtering")
    assert d.wording in ("Possible", "Likely")
    assert any("not proof" in c for c in d.caveats)
    assert d.confidence < 0.95


def test_case_c_tcp_ok_tls_failed_http_failed():
    results = [
        R("dns.ok", "dns_resolution", S.SUCCESS, meta={"role": "system"}),
        tcp("example.com", 443, S.OPEN),
        R("tls.example.com", "tls", S.TLS_FAILED, target="example.com", meta={"role": "handshake"},
          retry_outcome=RetryOutcome.PERSISTENT_FAILURE),
        R("http.1", "http", S.HTTP_FAILED),
    ]
    s = analyze(results)
    d = next(d for d in s.diagnoses if d.diagnosis_id == "tls_failure")
    assert "TCP works" in d.title and d.confidence >= 0.75
    assert s.overall is OverallStatus.DEGRADED


def test_certificate_error_is_not_reported_as_tls_filtering():
    results = [tcp("example.com", 443, S.OPEN),
               R("tls.example.com", "tls", S.TLS_FAILED, target="example.com", error_code="CERTIFICATE_ERROR",
                 meta={"role": "handshake"})]
    assert "tls_failure" not in ids(analyze(results))


def test_case_d_icmp_blocked_internet_fine():
    results = [R("icmp.1", "icmp", S.TIMEOUT), tcp("example.com", 443, S.OPEN),
               R("http.1", "http", S.SUCCESS)]
    s = analyze(results)
    d = next(d for d in s.diagnoses if d.diagnosis_id == "icmp_blocked")
    assert d.severity is Severity.INFO
    assert "internet_unavailable" not in ids(s)


def test_ping_failure_alone_never_means_internet_down():
    s = analyze([R("icmp.1", "icmp", S.TIMEOUT), R("icmp.2", "icmp", S.TIMEOUT)])
    assert "internet_unavailable" not in ids(s)
    assert s.overall is OverallStatus.INCONCLUSIVE


def test_case_e_ipv6_broken_vs_not_configured():
    v4 = R("ipv4", "ip_family", S.SUCCESS, address_family="IPv4")
    broken = R("ipv6", "ip_family", S.TIMEOUT, address_family="IPv6", metrics={"configured": True, "default_route": True})
    none = R("ipv6", "ip_family", S.UNREACHABLE, address_family="IPv6", metrics={"configured": False})
    assert "ipv6_broken" in ids(analyze([v4, broken]))
    s = analyze([v4, none])
    d = next(d for d in s.diagnoses if d.diagnosis_id == "ipv6_not_configured")
    assert d.severity is Severity.INFO and d.measured


def test_case_f_quality_degradation_not_port_problem():
    results = [tcp("example.com", 443, S.OPEN),
               R("lat.1", "latency", S.PARTIAL, target="1.1.1.1", metrics={"average_ms": 400, "packet_loss_percent": 25})]
    d = next(d for d in analyze(results).diagnoses if d.diagnosis_id == "quality_degraded")
    assert "not a port-availability problem" in d.title


def test_full_outage_is_one_diagnosis_not_a_cascade():
    results = [R("gateway", "gateway", S.TIMEOUT), tcp("1.1.1.1", 443, S.TIMEOUT, ip=True),
               tcp("8.8.8.8", 443, S.TIMEOUT, ip=True), R("icmp.1", "icmp", S.TIMEOUT),
               R("dns.sys", "dns_resolution", S.DNS_FAILED, meta={"role": "system"})]
    s = analyze(results)
    assert s.overall is OverallStatus.DISRUPTED
    assert ids(s) == {"internet_unavailable"}
    assert "gateway" in s.diagnoses[0].title.lower()


def test_vpn_is_evidence_not_failure():
    results = [R("vpn", "vpn", S.SUCCESS, meta={"detected": True, "detail": "WireGuard adapter"}),
               tcp("example.com", 443, S.OPEN), R("icmp.1", "icmp", S.SUCCESS), R("http.1", "http", S.SUCCESS)]
    s = analyze(results)
    d = next(d for d in s.diagnoses if d.diagnosis_id == "vpn_detected")
    assert d.severity is Severity.INFO and d.wording == "Detected"
    assert s.overall is OverallStatus.HEALTHY


def test_sni_selective_failure_is_possible_not_proven():
    r = R("tls.sni", "tls", S.TLS_FAILED, meta={"role": "sni_probe"}, interpretation="SNI_SELECTIVE_FAILURE")
    r.add_evidence("TLS with SNI failed; TLS without SNI succeeded")
    d = next(d for d in analyze([r]).diagnoses if d.diagnosis_id == "sni_filtering")
    assert d.wording in ("Possible", "Likely") and any("not proof" in c for c in d.caveats)


def test_site_failures_need_working_control_sites():
    ctl = R("site.ctl", "site", S.SUCCESS, target="ctl.com", meta={"role": "control"})
    bad = R("site.a", "site", S.DNS_FAILED, target="a.com", meta={"role": "test", "failed_layer": "dns"})
    assert "site_dns" in ids(analyze([ctl, bad]))
    assert "site_dns" not in ids(analyze([bad]))


def test_blocked_tests_are_listed():
    skipped = R("tls", "tls", S.SKIPPED)
    skipped.metadata.update(skip_reason="BLOCKED_BY_DEPENDENCY", blocked_by=["dns"])
    s = analyze([skipped])
    assert s.blocked == [{"test_id": "tls", "blocked_by": ["dns"], "reason": "BLOCKED_BY_DEPENDENCY"}]


def test_confidence_is_bounded_and_wording_follows_it():
    from app.diag.correlation import clamp_confidence, wording_for
    assert clamp_confidence(5) == 0.95 and clamp_confidence(-1) == 0.05
    assert wording_for(0.8) == "Likely" and wording_for(0.5) == "Possible" and wording_for(0.2) == "Inconclusive"
