"""Foundation: result model, error normalization, retry policy, dependency graph."""
import errno
import socket
import ssl
import threading
import time

import pytest

from app.diag.graph import DependencyGraph, GraphRunner, Node, SKIP_BLOCKED, SKIP_CANCELLED
from app.diag.neterrors import normalize_exception, normalize_os_error
from app.diag.results import RetryOutcome, Severity, TechnicalStatus as S, TestResult, to_legacy_status
from app.diag.retry import Cancelled, run_with_retry
from app.diag.testconfig import NetworkTestConfig, RetryPolicy
from app.models import Status


# ---- result model ----------------------------------------------------------
def test_timeout_is_not_closed_and_severity_is_independent():
    r = TestResult("tcp.x.25", "tcp", status=S.TIMEOUT)
    assert r.status is not S.CLOSED
    assert r.severity is Severity.WARNING
    r2 = TestResult("tcp.x.25", "tcp", status=S.TIMEOUT, severity=Severity.ERROR)
    assert r2.status is S.TIMEOUT and r2.severity is Severity.ERROR


@pytest.mark.parametrize("status,expected", [
    (S.SUCCESS, Status.OK), (S.OPEN, Status.OK), (S.CLOSED, Status.OK),
    (S.TIMEOUT, Status.WARNING), (S.DNS_FAILED, Status.FAILED), (S.RESET, Status.FAILED),
    (S.INCONCLUSIVE, Status.UNKNOWN), (S.OPEN_OR_FILTERED, Status.UNKNOWN), (S.SKIPPED, Status.UNKNOWN),
])
def test_legacy_status_adapter(status, expected):
    assert to_legacy_status(TestResult("t", "c", status=status)) is expected


def test_result_roundtrip_keeps_evidence_and_codes():
    r = TestResult("tcp.a.443", "tcp", status=S.TIMEOUT, port=443, error_code="TIMEOUT",
                   platform_error=10060, interpretation="POSSIBLY_FILTERED", confidence=0.6)
    r.add_evidence("no SYN/ACK within 2.5 s")
    back = TestResult.from_dict(r.to_dict())
    assert back.status is S.TIMEOUT and back.platform_error == 10060
    assert back.evidence[0].text.startswith("no SYN")
    assert back.interpretation == "POSSIBLY_FILTERED"


def test_from_dict_tolerates_garbage():
    back = TestResult.from_dict({"status": "NOPE", "severity": "??", "started_at": "bad"})
    assert back.status is S.UNKNOWN


# ---- error normalization -----------------------------------------------------
@pytest.mark.parametrize("number,code,status", [
    (10060, "TIMEOUT", S.TIMEOUT), (10061, "CONNECTION_REFUSED", S.CLOSED),
    (10054, "CONNECTION_RESET", S.RESET), (10051, "NETWORK_UNREACHABLE", S.UNREACHABLE),
    (10065, "HOST_UNREACHABLE", S.UNREACHABLE), (10013, "PERMISSION_DENIED", S.ERROR),
    (errno.ECONNREFUSED, "CONNECTION_REFUSED", S.CLOSED), (errno.ETIMEDOUT, "TIMEOUT", S.TIMEOUT),
    (errno.ENETUNREACH, "NETWORK_UNREACHABLE", S.UNREACHABLE),
    (errno.EHOSTUNREACH, "HOST_UNREACHABLE", S.UNREACHABLE),
])
def test_os_error_numbers_map_on_both_platforms(number, code, status):
    n = normalize_os_error(number)
    assert (n.error_code, n.status) == (code, status)
    assert n.platform_error == number


def test_windows_wsa_names_are_preserved():
    assert normalize_os_error(10060).platform_name == "WSAETIMEDOUT"
    assert normalize_os_error(11001).platform_name == "WSAHOST_NOT_FOUND"
    assert normalize_os_error(11002).error_code == "DNS_TEMPORARY_FAILURE"


def test_exception_normalization():
    assert normalize_exception(socket.timeout("timed out")).status is S.TIMEOUT
    assert normalize_exception(ConnectionRefusedError(errno.ECONNREFUSED, "refused")).status is S.CLOSED
    assert normalize_exception(ConnectionResetError(errno.ECONNRESET, "reset")).status is S.RESET
    assert normalize_exception(socket.gaierror(socket.EAI_NONAME, "no")).error_code == "HOST_NOT_FOUND"
    assert normalize_exception(socket.gaierror(11002, "again")).error_code == "DNS_TEMPORARY_FAILURE"
    cert = normalize_exception(ssl.SSLCertVerificationError(1, "bad cert"))
    assert cert.error_code == "CERTIFICATE_ERROR" and cert.status is S.TLS_FAILED
    odd = normalize_exception(ValueError("x" * 500))
    assert odd.status is S.ERROR and len(odd.error_message) <= 200


# ---- retry policy ------------------------------------------------------------
def _probe_sequence(codes):
    seq = list(codes)

    def probe(attempt):
        code = seq.pop(0)
        if code is None:
            return TestResult("t", "tcp", status=S.OPEN)
        return TestResult("t", "tcp", status=S.TIMEOUT, error_code=code)
    return probe


NOSLEEP = lambda _s: None  # noqa: E731


def test_first_attempt_success_has_no_retry():
    r = run_with_retry(_probe_sequence([None]), RetryPolicy(), sleep=NOSLEEP)
    assert r.attempts == 1 and r.retry_outcome is RetryOutcome.FIRST_ATTEMPT_OK


def test_retry_recovery_is_reported_as_recovered():
    r = run_with_retry(_probe_sequence(["TIMEOUT", None]), RetryPolicy(max_retries=1), sleep=NOSLEEP)
    assert r.ok and r.attempts == 2
    assert r.retry_outcome is RetryOutcome.RECOVERED_AFTER_RETRY
    assert r.warnings and len(r.metadata["attempt_log"]) == 2


def test_persistent_failure_after_retries():
    r = run_with_retry(_probe_sequence(["TIMEOUT", "TIMEOUT", "TIMEOUT"]), RetryPolicy(max_retries=2), sleep=NOSLEEP)
    assert not r.ok and r.attempts == 3 and r.retry_outcome is RetryOutcome.PERSISTENT_FAILURE


def test_deterministic_failure_is_not_retried():
    r = run_with_retry(_probe_sequence(["CONNECTION_REFUSED", None]), RetryPolicy(max_retries=3), sleep=NOSLEEP)
    assert r.attempts == 1 and r.retry_outcome is RetryOutcome.NOT_RETRIED


def test_intermittent_when_mixed():
    r = run_with_retry(_probe_sequence(["TIMEOUT", None]), RetryPolicy(max_retries=1), sleep=NOSLEEP)
    assert r.retry_outcome is RetryOutcome.RECOVERED_AFTER_RETRY


def test_cancel_before_first_attempt():
    ev = threading.Event(); ev.set()
    with pytest.raises(Cancelled):
        run_with_retry(_probe_sequence([None]), RetryPolicy(), cancel=ev)


# ---- config ------------------------------------------------------------------
def test_config_validation():
    with pytest.raises(ValueError):
        NetworkTestConfig(max_concurrency=0)
    assert NetworkTestConfig().targets.connectivity  # separate target groups exist


# ---- dependency graph ----------------------------------------------------------
def _node(nid, status=S.SUCCESS, hard=(), soft=(), delay=0.0, log=None, **kw):
    def run(ctx):
        if log is not None:
            log.append(("start", nid, time.perf_counter()))
        time.sleep(delay)
        if log is not None:
            log.append(("end", nid, time.perf_counter()))
        return [TestResult(nid, "x", status=status)]
    return Node(nid, run, hard=tuple(hard), soft=tuple(soft), **kw)


def test_dependency_propagation_blocks_downstream_without_fake_failures():
    g = DependencyGraph([
        _node("dns", S.DNS_FAILED), _node("tls", hard=["dns"]), _node("http", hard=["tls"]),
    ])
    ctx = GraphRunner(g).run()
    assert ctx.results["dns"][0].status is S.DNS_FAILED
    for nid, by in (("tls", ["dns"]), ("http", ["tls"])):
        r = ctx.results[nid][0]
        assert r.status is S.SKIPPED and r.metadata["skip_reason"] == SKIP_BLOCKED
        assert r.metadata["blocked_by"] == by


def test_soft_dependency_never_blocks():
    g = DependencyGraph([_node("gateway", S.TIMEOUT), _node("dns", soft=["gateway"])])
    ctx = GraphRunner(g).run()
    assert ctx.results["dns"][0].status is S.SUCCESS


def test_unselected_dependency_does_not_block():
    ctx = GraphRunner(DependencyGraph([_node("tls", hard=["dns"])])).run()
    assert ctx.results["tls"][0].status is S.SUCCESS


def test_cycle_and_duplicates_are_rejected():
    with pytest.raises(ValueError):
        DependencyGraph([_node("a", hard=["b"]), _node("b", hard=["a"])])
    with pytest.raises(ValueError):
        DependencyGraph([_node("a"), _node("a")])


def test_concurrency_is_bounded_and_exclusive_runs_alone():
    active, peak = [0], [0]
    lock = threading.Lock()

    def work(ctx):
        with lock:
            active[0] += 1; peak[0] = max(peak[0], active[0])
        time.sleep(0.05)
        with lock:
            active[0] -= 1
        return [TestResult("n", "x", status=S.SUCCESS)]

    nodes = [Node(f"n{i}", work) for i in range(10)]
    GraphRunner(DependencyGraph(nodes), max_workers=3).run()
    assert peak[0] <= 3

    log = []
    g = DependencyGraph([_node("a", delay=0.05, log=log), _node("b", delay=0.05, log=log),
                         _node("ex", delay=0.05, log=log, exclusive=True)])
    GraphRunner(g, max_workers=4).run()
    ex_start = next(t for k, n, t in log if k == "start" and n == "ex")
    ex_end = next(t for k, n, t in log if k == "end" and n == "ex")
    others = [t for k, n, t in log if n != "ex"]
    assert not any(ex_start < t < ex_end for t in others)


def test_crashing_node_becomes_error_result_not_exception():
    def boom(ctx):
        raise RuntimeError("kaboom")
    ctx = GraphRunner(DependencyGraph([Node("bad", boom)])).run()
    r = ctx.results["bad"][0]
    assert r.status is S.ERROR and "kaboom" in r.error_message


def test_cancellation_skips_pending_and_leaves_no_threads():
    cancel = threading.Event()

    def first(ctx):
        cancel.set()
        return [TestResult("first", "x", status=S.SUCCESS)]

    g = DependencyGraph([Node("first", first), _node("second", hard=["first"]), _node("third", soft=["second"])])
    before = threading.active_count()
    ctx = GraphRunner(g, cancel=cancel).run()
    assert ctx.results["second"][0].metadata["skip_reason"] == SKIP_CANCELLED
    assert threading.active_count() <= before


def test_severity_follows_status_changes_until_set_explicitly():
    r = TestResult("t", "c")                       # UNKNOWN -> INFO
    assert r.severity is Severity.INFO
    r.status = S.TIMEOUT
    assert r.severity is Severity.WARNING
    r.status = S.DNS_FAILED
    assert r.severity is Severity.ERROR
    r.severity = Severity.INFO                     # explicit override sticks
    r.status = S.TIMEOUT
    assert r.severity is Severity.INFO
    r.severity = None                              # back to automatic
    assert r.severity is Severity.WARNING
    assert TestResult("t", "c", status=S.OPEN).severity is Severity.OK
    assert TestResult("t", "c", status=S.OPEN, severity=Severity.ERROR).severity is Severity.ERROR
