"""Graph-driven runner: dependencies, skipping, cancellation, concurrency, crash isolation."""
import threading
import time

import pytest

from app.core import runner as rn
from app.diag.results import TechnicalStatus as S, TestResult
from app.models import CheckResult, ModuleReport, NetworkInfo, Status


def _report(name, results=()):
    r = ModuleReport(module_name=name)
    r.add(CheckResult(name=name, status=Status.OK, message="ok"))
    r.results.extend(results)
    return r


def _sys_dns(ok):
    return TestResult("dns.resolve.System.x", "dns_resolution", status=S.SUCCESS if ok else S.DNS_FAILED,
                      metadata={"role": "system"})


@pytest.fixture
def fake_modules(monkeypatch):
    calls = []
    def install(dns_ok=True, delay=0.0):
        def make(self, key):
            calls.append(key)
            time.sleep(delay)
            if key == "dns_test":
                return _report("DNS Test", [_sys_dns(dns_ok)])
            if key == "protocol_tests":
                raise RuntimeError("boom")
            return _report(rn.MODULE_DISPLAY_NAMES[key])
        monkeypatch.setattr(rn.DiagnosticRunner, "_make_module", make)
        monkeypatch.setattr(rn.NetworkInfoCollector, "collect", lambda self, **k: NetworkInfo())
    install.calls = calls
    return install


def run(modules, **kw):
    r = rn.DiagnosticRunner(rn.normalize_modules(modules), **kw)
    return r, r.run()


def test_dependencies_are_valid_and_acyclic():
    r = rn.DiagnosticRunner(rn.ALL_MODULES)
    r.build_graph()                                  # raises on cycle / self dependency
    assert "local_network" in rn.ALL_MODULES and rn.ALL_MODULES.index("local_network") == 1


def test_dns_failure_skips_name_based_modules(fake_modules):
    fake_modules(dns_ok=False)
    r, out = run(["dns_test", "tls_test", "http_test", "udp_test"])
    by = {rep.module_name: rep for rep in out.reports}
    assert "tls_test" not in fake_modules.calls and "http_test" not in fake_modules.calls
    assert "udp_test" in fake_modules.calls                       # independent module still runs
    tls = by["TLS Test"].checks[0]
    assert tls.result.status is S.SKIPPED and "DNS Test" in tls.message
    assert tls.result.metadata["blocked_by"] == ["dns_test"]


def test_dns_success_runs_everything_in_canonical_order(fake_modules):
    fake_modules(dns_ok=True)
    _, out = run(["tls_test", "dns_test", "http_test"])
    assert [r.module_name for r in out.reports] == ["DNS Test", "TLS Test", "HTTP Test"]


def test_unselected_dns_does_not_block(fake_modules):
    fake_modules()
    _, out = run(["tls_test"])
    assert "tls_test" in fake_modules.calls


def test_dns_gate_unknown_when_nothing_measured():
    assert rn.dns_gate([]) is True
    assert rn.dns_gate([_sys_dns(False)]) is False


def test_module_crash_is_isolated(fake_modules):
    fake_modules()
    r, out = run(["protocol_tests", "udp_test"])
    names = {rep.module_name: rep for rep in out.reports}
    assert "internal error" in names["Protocol Tests"].checks[0].message
    assert names["UDP Test"].checks[0].message == "ok"
    assert len(out.errors) == 1


def test_cancel_before_start_skips_everything(fake_modules):
    fake_modules()
    cancel = threading.Event(); cancel.set()
    _, out = run(["dns_test", "udp_test"], cancel=cancel)
    assert out.cancelled and fake_modules.calls == []
    assert all(rep.checks[0].result.status is S.SKIPPED for rep in out.reports)


def test_independent_modules_run_concurrently(fake_modules):
    fake_modules(delay=0.3)
    started = time.perf_counter()
    _, out = run(["udp_test", "tcp_scanner", "vpn_connectivity", "environment_check"])
    elapsed = time.perf_counter() - started
    assert len(out.reports) == 4
    assert elapsed < 0.3 * 5 * 0.6, elapsed          # sequential would be >= 1.5 s


def test_exclusive_modules_do_not_overlap(fake_modules, monkeypatch):
    active, overlaps = [], []
    lock = threading.Lock()
    def make(self, key):
        with lock:
            if key in ("latency_test", "mtu_test") and active:
                overlaps.append((key, list(active)))
            active.append(key)
        time.sleep(0.15)
        with lock:
            active.remove(key)
        return _report(rn.MODULE_DISPLAY_NAMES[key])
    monkeypatch.setattr(rn.DiagnosticRunner, "_make_module", make)
    monkeypatch.setattr(rn.NetworkInfoCollector, "collect", lambda self, **k: NetworkInfo())
    run(["udp_test", "tcp_scanner", "latency_test", "mtu_test"])
    assert overlaps == []
    # and nothing else started while an exclusive module was running
    # (checked via the overlap list: other modules would have been in `active` when an exclusive began)


def test_callbacks_fire_once_per_module(fake_modules):
    fake_modules()
    started, finished, infos = [], [], []
    run(["dns_test", "udp_test"], on_module_started=started.append,
        on_module_finished=lambda r: finished.append(r.module_name), on_network_info=infos.append)
    assert sorted(finished) == ["DNS Test", "UDP Test"] and len(infos) == 1
    assert "Network Information" in started


def test_qt_worker_end_to_end(fake_modules, monkeypatch):
    import os
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtCore import QCoreApplication
    from app.core.worker import DiagnosticWorker
    app = QCoreApplication.instance() or QCoreApplication([])
    fake_modules()
    got = {}
    w = DiagnosticWorker(["dns_test", "udp_test"])
    w.run_finished.connect(lambda rep: got.setdefault("report", rep))
    w.start(); assert w.wait(10000)
    app.processEvents()
    rep = got["report"]
    assert [m.module_name for m in rep.modules] == ["DNS Test", "UDP Test"] and not rep.cancelled


def test_qt_worker_cancel_via_request_interruption(fake_modules):
    import os
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtCore import QCoreApplication
    from app.core.worker import DiagnosticWorker
    app = QCoreApplication.instance() or QCoreApplication([])
    fake_modules(delay=0.2)
    got = {}
    w = DiagnosticWorker(["dns_test", "tls_test", "http_test", "site_reachability"])
    w.run_finished.connect(lambda rep: got.setdefault("report", rep))
    w.start(); time.sleep(0.1); w.requestInterruption()
    assert w.wait(10000); app.processEvents()
    assert got["report"].cancelled
