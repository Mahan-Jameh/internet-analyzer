from app.core.tls_test import TLSTester
from app.models import Status


def _probe(monkeypatch, outcomes):
    tester = TLSTester()
    monkeypatch.setattr("app.core.tls_test.resolve_host", lambda *a, **k: ["1.2.3.4"])
    monkeypatch.setattr(tester, "_probe_sni", lambda ip, sni: outcomes(sni))
    return tester._sni_filtering_probe()


def test_all_generic_errors_is_not_an_all_clear(monkeypatch):
    result = _probe(monkeypatch, lambda sni: "error")
    assert result.status == Status.UNKNOWN


def test_cut_for_some_names_only_is_flagged_as_possible(monkeypatch):
    result = _probe(monkeypatch, lambda sni: "reset" if sni == "example.com" else "ok")
    assert result.status == Status.WARNING
    assert result.details["suspected"] is True
    assert "not proof" in result.message


def test_cut_for_every_name_points_at_the_address_not_the_sni(monkeypatch):
    result = _probe(monkeypatch, lambda sni: "timeout")
    assert result.status == Status.FAILED
    assert result.details["suspected"] is False


def test_same_behaviour_everywhere_is_ok(monkeypatch):
    assert _probe(monkeypatch, lambda sni: "ok").status == Status.OK
    assert _probe(monkeypatch, lambda sni: "alert").status == Status.OK
