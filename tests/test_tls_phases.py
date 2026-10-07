"""TLS phase results against a real local TLS server (no Internet needed)."""
import datetime
import ipaddress
import socket
import ssl
import struct
import threading

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from app.core.tls_test import TLSTester, classify_handshake_exception
from app.diag.correlation import analyze
from app.diag.results import RetryOutcome, Severity, TechnicalStatus as S
from app.diag.testconfig import NetworkTestConfig, RetryPolicy

CFG = NetworkTestConfig(tls_timeout=0.5, connect_timeout=0.5, retry=RetryPolicy(max_retries=1, backoff_seconds=0))


def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


@pytest.fixture(scope="module")
def pki(tmp_path_factory):
    d = tmp_path_factory.mktemp("pki")
    now = datetime.datetime.now(datetime.timezone.utc)
    ca_key = rsa.generate_private_key(65537, 2048)
    ca = (x509.CertificateBuilder().subject_name(_name("ICPA test CA")).issuer_name(_name("ICPA test CA"))
          .public_key(ca_key.public_key()).serial_number(1).not_valid_before(now - datetime.timedelta(days=1))
          .not_valid_after(now + datetime.timedelta(days=30))
          .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
          .sign(ca_key, hashes.SHA256()))
    key = rsa.generate_private_key(65537, 2048)
    cert = (x509.CertificateBuilder().subject_name(_name("localhost")).issuer_name(ca.subject)
            .public_key(key.public_key()).serial_number(2).not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=30))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost"),
                                                        x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), False)
            .sign(ca_key, hashes.SHA256()))
    paths = {"ca": d / "ca.pem", "cert": d / "cert.pem", "key": d / "key.pem"}
    paths["ca"].write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    paths["cert"].write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    paths["key"].write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                                               serialization.NoEncryption()))
    return {k: str(v) for k, v in paths.items()}


class Server:
    """mode: ok | silent (accepts TCP, never answers) | reset (RST right after accept)."""

    def __init__(self, pki, mode="ok", conns=8):
        self.mode, self.sock = mode, socket.socket()
        self.sock.bind(("127.0.0.1", 0)); self.sock.listen(16); self.sock.settimeout(3)
        self.port = self.sock.getsockname()[1]
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(pki["cert"], pki["key"]); self.ctx.set_alpn_protocols(["h2", "http/1.1"])
        self._held = []
        threading.Thread(target=self._loop, args=(conns,), daemon=True).start()

    def _loop(self, conns):
        for _ in range(conns):
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            if self.mode == "ok":
                threading.Thread(target=self._tls, args=(c,), daemon=True).start()
            elif self.mode == "reset":
                c.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0)); c.close()
            else:
                self._held.append(c)

    def _tls(self, c):
        try:
            with self.ctx.wrap_socket(c, server_side=True):
                pass
        except (ssl.SSLError, OSError):
            pass

    def close(self):
        self.sock.close()
        for c in self._held:
            c.close()


def make_tls_tester(pki, port, **kw):
    return TLSTester(["localhost"], config=CFG, port=port, ca_file=pki["ca"], **kw)


V13 = ssl.TLSVersion.TLSv1_3


def test_tls_success_collects_phase_timings_and_certificate(pki):
    srv = Server(pki)
    try:
        r = make_tls_tester(pki, srv.port).handshake_phases("localhost", V13, V13, alpn=["h2"])
        assert r.status is S.SUCCESS and r.metrics["tls_version"] == "TLSv1.3"
        assert r.metrics["alpn"] == "h2" and r.metrics["hostname_match"] is True
        assert {"dns_ms", "tcp_ms", "handshake_ms"} <= set(r.metrics)
        assert r.metrics["cert_days_left"] >= 28 and r.metadata["tcp_ok"]
    finally:
        srv.close()


def test_certificate_failure_is_not_a_generic_tls_failure(pki):
    srv = Server(pki)
    try:                                              # no ca_file -> the test CA is unknown
        r = TLSTester(["localhost"], config=CFG, port=srv.port).handshake_phases("localhost", V13, V13)
        assert r.status is S.TLS_FAILED and r.error_code == "CERTIFICATE_ERROR"
        assert r.metadata["phase"] == "certificate" and r.metadata["tcp_ok"]
    finally:
        srv.close()


def test_hostname_mismatch_is_its_own_outcome(pki):
    srv = Server(pki)
    try:
        r = make_tls_tester(pki, srv.port).handshake_phases("localhost", V13, V13, sni="wrong.example")
        assert r.error_code == "CERTIFICATE_HOSTNAME_MISMATCH" and r.severity is Severity.ERROR
    finally:
        srv.close()


def test_handshake_timeout_when_tcp_works_but_server_stays_silent(pki):
    srv = Server(pki, "silent")
    try:
        r = make_tls_tester(pki, srv.port).handshake_phases("localhost", V13, V13)
        assert r.status is S.TIMEOUT and r.error_code == "TLS_HANDSHAKE_TIMEOUT"
        assert r.metadata["tcp_ok"] is True and r.metadata["phase"] == "handshake"
        retried = make_tls_tester(pki, srv.port)._handshake_retrying("localhost", V13, V13)
        assert retried.attempts == 2 and retried.retry_outcome is RetryOutcome.PERSISTENT_FAILURE
    finally:
        srv.close()


def test_connection_reset_during_handshake(pki):
    srv = Server(pki, "reset")
    try:
        r = make_tls_tester(pki, srv.port).handshake_phases("localhost", V13, V13)
        assert r.status in (S.RESET, S.TLS_FAILED) and r.error_code in ("TLS_HANDSHAKE_RESET", "TLS_HANDSHAKE_EOF")
        assert r.metadata["tcp_ok"] is True
    finally:
        srv.close()


def test_tcp_failure_stops_before_tls(pki):
    s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()
    r = make_tls_tester(pki, port).handshake_phases("localhost", V13, V13)
    assert r.status is S.CLOSED and r.interpretation == "TCP_FAILED" and r.metadata["phase"] == "tcp"
    assert "tcp_ok" not in r.metadata


def test_dns_failure_stops_before_tcp(pki, monkeypatch):
    from app.core import tls_test
    from app.diag.neterrors import normalize_os_error
    from app.diag.probes import Resolution
    monkeypatch.setattr(tls_test, "resolve", lambda h, f=None, port=0: Resolution(h, None, None, [], 1.0, normalize_os_error(11001)))
    r = make_tls_tester(pki, 443).handshake_phases("nope.invalid", V13, V13)
    assert r.status is S.DNS_FAILED and r.metadata["phase"] == "dns" and r.interpretation == "DNS_FAILED"


def test_module_run_keeps_legacy_checks_and_structured_results(pki):
    srv = Server(pki, conns=20)
    try:
        t = make_tls_tester(pki, srv.port)
        t._sni_filtering_probe = lambda report=None: __import__("app.models", fromlist=["x"]).CheckResult("SNI Filtering Probe", __import__("app.models", fromlist=["x"]).Status.OK)
        rep = t.run_all()
        names = [c.name for c in rep.checks]
        for expected in ("TLS 1.3 Handshake (localhost)", "TLS 1.2 Handshake (localhost)",
                         "Certificate Validation (localhost)", "SNI Support (localhost)",
                         "ALPN Negotiation (localhost)", "Cipher Suite (localhost)"):
            assert expected in names
        hs = [r for r in rep.results if r.metadata.get("role") == "handshake"]
        assert len(hs) == 2 and all(r.ok for r in hs)
    finally:
        srv.close()


def test_one_tls_version_failing_is_only_a_warning(pki):
    srv = Server(pki, conns=20)
    try:
        t = make_tls_tester(pki, srv.port)
        real = t.handshake_phases

        def fake(host, min_v, max_v, **kw):
            if min_v == ssl.TLSVersion.TLSv1_3:
                r = real(host, min_v, max_v, **kw); r.status = S.TLS_FAILED; r.error_code = "TLS_PROTOCOL_ERROR"; return r
            return real(host, min_v, max_v, **kw)
        t.handshake_phases = fake
        t._sni_filtering_probe = lambda report=None: __import__("app.models", fromlist=["x"]).CheckResult("x", __import__("app.models", fromlist=["x"]).Status.OK)
        checks = {c.name: c for c in t.run_all().checks}
        assert checks["TLS 1.3 Handshake (localhost)"].status.value == "WARNING"
    finally:
        srv.close()


def test_tcp_ok_tls_failing_leads_to_a_tls_diagnosis(pki):
    srv = Server(pki, "silent", conns=20)
    try:
        t = make_tls_tester(pki, srv.port)
        t._sni_filtering_probe = lambda report=None: None
        rep = t.run_all()
        summary = analyze(rep.results)
        d = next(d for d in summary.diagnoses if d.diagnosis_id == "tls_failure")
        assert "TCP works" in d.title and d.wording in ("Possible", "Likely")
    finally:
        srv.close()


def test_exception_classification_table():
    assert classify_handshake_exception(socket.timeout())[1] == "TLS_HANDSHAKE_TIMEOUT"
    assert classify_handshake_exception(ConnectionResetError(104, "x"))[1] == "TLS_HANDSHAKE_RESET"
    assert classify_handshake_exception(ssl.SSLEOFError())[1] == "TLS_HANDSHAKE_EOF"
    assert classify_handshake_exception(ssl.SSLError("alert"))[1] == "TLS_PROTOCOL_ERROR"
    assert classify_handshake_exception(ssl.SSLCertVerificationError(1, "expired"))[1] == "CERTIFICATE_ERROR"


# ---- SNI comparison -------------------------------------------------------------------------------
def probe(monkeypatch, outcomes):
    t = TLSTester(config=CFG)
    monkeypatch.setattr("app.core.tls_test.resolve_host", lambda *a, **k: ["1.2.3.4"])
    monkeypatch.setattr(t, "_probe_sni", lambda ip, sni: outcomes(sni))
    return t._sni_filtering_probe()


def test_sni_blocked_but_no_sni_works_is_evidence_with_higher_confidence(monkeypatch):
    check = probe(monkeypatch, lambda sni: "reset" if sni == "www.cloudflare.com" else "ok")
    r = check.result
    assert r.interpretation == "SNI_SELECTIVE_FAILURE" and 0.7 <= r.confidence <= 0.85
    assert r.metrics["outcomes"]["(no SNI)"] == "ok" and "not proof" in r.summary
    assert any("TCP/443" in e.text for e in r.evidence)


def test_sni_probe_confirms_a_cut_before_believing_it(monkeypatch):
    seen = []
    def outcomes(sni):
        seen.append(sni)
        return "reset" if (sni == "example.com" and seen.count("example.com") == 1) else "ok"
    check = probe(monkeypatch, outcomes)
    assert check.result.status is S.SUCCESS             # the second attempt succeeded: it was a blip
    assert seen.count("example.com") == 2


def test_sni_probe_feeds_the_correlation_engine(monkeypatch):
    check = probe(monkeypatch, lambda sni: "timeout" if sni == "www.cloudflare.com" else "ok")
    d = next(d for d in analyze([check.result]).diagnoses if d.diagnosis_id == "sni_filtering")
    assert d.wording in ("Possible", "Likely") and d.confidence <= 0.85


def test_no_sni_handshake_works_against_a_local_server(pki):
    srv = Server(pki)
    try:
        assert TLSTester(config=CFG, port=srv.port)._probe_sni("127.0.0.1", None) == "ok"
    finally:
        srv.close()
