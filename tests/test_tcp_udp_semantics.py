"""TCP and UDP result semantics: open / closed / timeout / refused / unreachable / response / silence."""
import socket
import threading

import pytest

from app.core import tcp_scanner as tcpmod
from app.core.tcp_scanner import TCPScanner
from app.core.udp_test import (UDPTester, build_dns_query, validate_dns_reply, validate_ntp_reply)
from app.diag import probes
from app.diag.neterrors import normalize_os_error
from app.diag.results import RetryOutcome, TechnicalStatus as S
from app.diag.testconfig import NetworkTestConfig, RetryPolicy

FAST = NetworkTestConfig(connect_timeout=0.3, udp_timeout=0.3, retry=RetryPolicy(max_retries=1, backoff_seconds=0))


def fake_attempt(*codes):
    """Replace the raw connect with a scripted sequence of OS error numbers (0 = success)."""
    seq = list(codes)

    def attempt(ip, port, timeout):
        code = seq.pop(0) if len(seq) > 1 else seq[0]
        if code == 0:
            return None, 12.0, "192.168.1.10"
        return normalize_os_error(code), 2500.0, None
    return attempt


@pytest.fixture
def scanner():
    return TCPScanner(target_host="203.0.113.7", config=FAST)


def test_tcp_open_real_localhost():
    srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(1)
    try:
        r = probes.tcp_probe("127.0.0.1", srv.getsockname()[1], FAST)
        assert r.status is S.OPEN and r.resolved_ip == "127.0.0.1" and r.address_family == "IPv4"
        assert r.protocol == "TCP" and r.duration_ms is not None
    finally:
        srv.close()


def test_tcp_closed_real_localhost_is_refused_not_timeout():
    spare = socket.socket(); spare.bind(("127.0.0.1", 0)); port = spare.getsockname()[1]; spare.close()
    r = probes.tcp_probe("127.0.0.1", port, FAST)
    assert r.status is S.CLOSED and r.error_code == "CONNECTION_REFUSED"
    assert r.interpretation == "ACTIVELY_REFUSED"
    assert r.attempts == 1                       # refusals are deterministic: no retry


@pytest.mark.parametrize("wsa,expected,code", [
    (10061, S.CLOSED, "CONNECTION_REFUSED"), (10060, S.TIMEOUT, "TIMEOUT"),
    (10054, S.RESET, "CONNECTION_RESET"), (10051, S.UNREACHABLE, "NETWORK_UNREACHABLE"),
    (10065, S.UNREACHABLE, "HOST_UNREACHABLE"),
])
def test_windows_codes_become_distinct_states(monkeypatch, scanner, wsa, expected, code):
    monkeypatch.setattr(probes, "tcp_attempt", fake_attempt(wsa))
    r = scanner.scan_port(25)
    assert r.status is expected and r.error_code == code and r.platform_error == wsa


def test_timeout_is_never_reported_as_closed(monkeypatch, scanner):
    monkeypatch.setattr(probes, "tcp_attempt", fake_attempt(10060))
    r = scanner.scan_port(25)
    assert r.status is S.TIMEOUT and r.status is not S.CLOSED
    assert r.interpretation == "FILTERED_OR_UNREACHABLE" and r.confidence <= 0.5
    assert r.retry_outcome is RetryOutcome.PERSISTENT_FAILURE and r.attempts == 2
    legacy = scanner.probe_port(25)
    assert legacy.state == "timeout"


def test_other_open_ports_raise_filtered_confidence(monkeypatch, scanner):
    def attempt(ip, port, timeout):
        return (None, 10.0, None) if port == 443 else (normalize_os_error(10060), 300.0, None)
    monkeypatch.setattr(probes, "tcp_attempt", attempt)
    scanner.ports = [25, 443]
    res = {r.port: r for r in scanner.scan()}
    assert res[443].status is S.OPEN
    assert res[25].interpretation == "POSSIBLY_FILTERED" and res[25].confidence >= 0.75


def test_retry_recovery_is_visible(monkeypatch, scanner):
    monkeypatch.setattr(probes, "tcp_attempt", fake_attempt(10060, 0))
    r = scanner.scan_port(443)
    assert r.status is S.OPEN and r.retry_outcome is RetryOutcome.RECOVERED_AFTER_RETRY and r.attempts == 2


def test_dns_failure_blocks_port_probes_instead_of_cascading(monkeypatch):
    monkeypatch.setattr(probes.socket, "getaddrinfo",
                        lambda *a, **k: (_ for _ in ()).throw(socket.gaierror(11001, "no such host")))
    results = TCPScanner(target_host="nope.invalid", ports=[80, 443], config=FAST).scan()
    assert results[0].status is S.DNS_FAILED and results[0].error_code == "HOST_NOT_FOUND"
    assert all(r.status is S.SKIPPED and r.metadata["skip_reason"] == "BLOCKED_BY_DEPENDENCY" for r in results[1:])


def test_scan_cancellation_skips_remaining_ports(monkeypatch):
    monkeypatch.setattr(probes, "tcp_attempt", fake_attempt(0))
    cancel = threading.Event(); cancel.set()
    results = TCPScanner(target_host="203.0.113.7", ports=[80, 443], config=FAST, cancel=cancel).scan()
    assert all(r.status is S.SKIPPED and r.metadata["skip_reason"] == "CANCELLED" for r in results)


def test_module_report_keeps_legacy_keys_and_detailed_result(monkeypatch, scanner):
    monkeypatch.setattr(probes, "tcp_attempt", fake_attempt(0))
    scanner.ports = [443]
    check = scanner.run_all().checks[0]
    assert check.details["state"] == "open" and check.details["port"] == 443
    assert check.result.status is S.OPEN and check.status.value == "OK"
    assert "result" in check.to_dict()


def test_ipv6_literal_is_marked_as_ipv6(monkeypatch):
    monkeypatch.setattr(probes, "tcp_attempt", fake_attempt(0))
    r = probes.tcp_probe("2606:4700:4700::1111", 443, FAST)
    assert r.address_family == "IPv6" and r.metadata["target_is_ip"] is True


# ---- UDP -------------------------------------------------------------------
def _udp_server(reply=b"pong"):
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); srv.bind(("127.0.0.1", 0)); srv.settimeout(2)

    def run():
        try:
            _data, addr = srv.recvfrom(2048)
            if reply is not None:
                srv.sendto(reply, addr)
        except OSError:
            pass
    threading.Thread(target=run, daemon=True).start()
    return srv


def test_udp_response_is_open():
    srv = _udp_server(b"pong")
    try:
        t = UDPTester(config=FAST)
        r = t._attempt("127.0.0.1", "127.0.0.1", srv.getsockname()[1], 1)
        assert r.status is S.OPEN and r.metrics["response_bytes"] == 4
    finally:
        srv.close()


def test_udp_silence_on_generic_probe_is_inconclusive_not_closed():
    srv = _udp_server(None)
    try:
        r = UDPTester(config=FAST)._attempt("127.0.0.1", "127.0.0.1", srv.getsockname()[1], 1)
        assert r.status is S.INCONCLUSIVE and r.status is not S.CLOSED
        assert r.interpretation == "NO_PROTOCOL_AWARE_PROBE"
    finally:
        srv.close()


def test_udp_silence_on_real_protocol_probe_is_open_or_filtered(monkeypatch):
    srv = _udp_server(None)
    try:
        t = UDPTester(config=FAST)
        monkeypatch.setattr(t, "_payload", lambda port: (b"q", lambda d: True, "dns-query"))
        r = t._attempt("127.0.0.1", "127.0.0.1", srv.getsockname()[1], 1)
        assert r.status is S.OPEN_OR_FILTERED and r.confidence <= 0.5
    finally:
        srv.close()


def test_udp_icmp_port_unreachable_is_closed():
    spare = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); spare.bind(("127.0.0.1", 0))
    port = spare.getsockname()[1]; spare.close()
    r = UDPTester(config=FAST)._attempt("127.0.0.1", "127.0.0.1", port, 1)
    assert r.status is S.CLOSED and r.interpretation == "ICMP_PORT_UNREACHABLE"


def test_dns_reply_validation_checks_transaction_id():
    packet, tid = build_dns_query()
    reply = bytearray(packet); reply[2] |= 0x80
    assert validate_dns_reply(bytes(reply), tid)
    assert not validate_dns_reply(bytes(reply), (tid + 1) & 0xFFFF)
    assert not validate_dns_reply(packet, tid)               # a query is not a response
    assert validate_ntp_reply(b"\x24" + b"\0" * 47) and not validate_ntp_reply(b"\x1b" + b"\0" * 47)


def test_udp_ports_are_limited_to_allow_list():
    assert UDPTester(ports=[53, 9999]).ports == [53]
