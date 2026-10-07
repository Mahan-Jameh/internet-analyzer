"""
tls_test.py
===========
Performs real TLS handshakes against well known hosts to check protocol
version support (TLS 1.2 / 1.3), certificate validation, handshake
timing, SNI, ALPN negotiation and negotiated cipher suite.
"""

from __future__ import annotations

import socket
import ssl
import time
from typing import Callable, Optional

from app.constants import (
    SNI_PROBE_BASELINE_HOST,
    SNI_PROBE_NAMES,
    TLS_TEST_HOSTS,
    TLS_TEST_PORT,
    TLS_TIMEOUT,
)
from app.logger import get_logger
from app.models import CheckResult, ModuleReport, Status
from app.utils.helpers import resolve_host

log = get_logger(__name__)

ProgressCallback = Optional[Callable[[str], None]]


class TLSTester:
    def __init__(self, hosts: Optional[list[str]] = None, progress_cb: ProgressCallback = None) -> None:
        self.hosts = hosts or TLS_TEST_HOSTS
        self.progress_cb = progress_cb

    def _report(self, message: str) -> None:
        if self.progress_cb:
            self.progress_cb(message)
        log.info(message)

    def _handshake(self, host: str, min_version: ssl.TLSVersion, max_version: ssl.TLSVersion,
                    verify: bool, alpn: Optional[list[str]] = None) -> tuple[bool, dict, str]:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = min_version
        context.maximum_version = max_version
        if verify:
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED
        else:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        if alpn:
            context.set_alpn_protocols(alpn)

        info: dict = {}
        try:
            with socket.create_connection((host, TLS_TEST_PORT), timeout=TLS_TIMEOUT) as sock:
                # Reaching this line means plain TCP worked. If the handshake
                # then fails, the failure is specific to TLS (not the address).
                info["tcp_connected"] = True
                with context.wrap_socket(sock, server_hostname=host) as tls_sock:
                    info["version"] = tls_sock.version()
                    info["cipher"] = tls_sock.cipher()
                    info["alpn_selected"] = tls_sock.selected_alpn_protocol()
                    cert = tls_sock.getpeercert()
                    info["certificate_present"] = cert is not None
            return True, info, ""
        except ssl.SSLCertVerificationError as exc:
            return False, info, f"Certificate verification failed: {exc}"
        except ssl.SSLError as exc:
            return False, info, f"TLS error: {exc}"
        except (socket.timeout, TimeoutError):
            return False, info, "Handshake timed out."
        except OSError as exc:
            return False, info, f"Connection error: {exc}"

    def run_all(self) -> ModuleReport:
        report = ModuleReport(module_name="TLS Test")

        for host in self.hosts:
            self._report(f"Testing TLS with {host} ...")

            # --- TLS 1.3 handshake with full certificate validation ------
            start = time.perf_counter()
            ok13, info13, err13 = self._handshake(
                host, ssl.TLSVersion.TLSv1_3, ssl.TLSVersion.TLSv1_3, verify=True,
                alpn=["h2", "http/1.1"],
            )
            duration13 = (time.perf_counter() - start) * 1000.0
            if ok13:
                report.add(CheckResult(
                    name=f"TLS 1.3 Handshake ({host})",
                    status=Status.OK,
                    message=f"Success in {duration13:.0f} ms. Cipher: {info13.get('cipher')}",
                    details=info13,
                    duration_ms=duration13,
                ))
            else:
                report.add(CheckResult(
                    name=f"TLS 1.3 Handshake ({host})",
                    status=Status.WARNING,
                    message=err13,
                    details=info13,
                    duration_ms=duration13,
                ))

            # --- TLS 1.2 handshake ---------------------------------------
            start = time.perf_counter()
            ok12, info12, err12 = self._handshake(
                host, ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_2, verify=True,
            )
            duration12 = (time.perf_counter() - start) * 1000.0
            if ok12:
                report.add(CheckResult(
                    name=f"TLS 1.2 Handshake ({host})",
                    status=Status.OK,
                    message=f"Success in {duration12:.0f} ms. Cipher: {info12.get('cipher')}",
                    details=info12,
                    duration_ms=duration12,
                ))
            else:
                report.add(CheckResult(
                    name=f"TLS 1.2 Handshake ({host})",
                    status=Status.WARNING,
                    message=err12,
                    details=info12,
                    duration_ms=duration12,
                ))

            # --- Certificate validation summary ---------------------------
            if ok13 or ok12:
                report.add(CheckResult(
                    name=f"Certificate Validation ({host})",
                    status=Status.OK,
                    message="Certificate chain validated successfully by the OS trust store.",
                ))
            else:
                report.add(CheckResult(
                    name=f"Certificate Validation ({host})",
                    status=Status.FAILED,
                    message="Could not complete a validated handshake to check the certificate.",
                ))

            # --- SNI support: the handshakes above used certificate AND
            #     hostname verification, so a success means the server returned
            #     a certificate that is valid for exactly the SNI name we sent.
            if ok13 or ok12:
                report.add(CheckResult(
                    name=f"SNI Support ({host})",
                    status=Status.OK,
                    message="Server returned a certificate matching the requested SNI name.",
                ))
            else:
                report.add(CheckResult(
                    name=f"SNI Support ({host})",
                    status=Status.WARNING,
                    message="SNI support could not be confirmed because no handshake completed.",
                ))

            # --- ALPN and cipher suite (taken from the TLS 1.3 handshake,
            #     falling back to the TLS 1.2 one).
            info = info13 if ok13 else info12
            if ok13 or ok12:
                alpn = info.get("alpn_selected")
                if ok13 and alpn:
                    report.add(CheckResult(
                        name=f"ALPN Negotiation ({host})",
                        status=Status.OK,
                        message=f"Server selected '{alpn}' via ALPN.",
                        details={"alpn_selected": alpn},
                    ))
                else:
                    report.add(CheckResult(
                        name=f"ALPN Negotiation ({host})",
                        status=Status.WARNING,
                        message="No ALPN protocol was negotiated (HTTP/2 cannot be used on this path).",
                        details={"alpn_selected": alpn},
                    ))

                cipher = info.get("cipher")
                if cipher:
                    report.add(CheckResult(
                        name=f"Cipher Suite ({host})",
                        status=Status.OK,
                        message=f"{cipher[0]} ({cipher[1]}, {cipher[2]} bits)",
                        details={"cipher": list(cipher)},
                    ))

        report.add(self._sni_filtering_probe())

        report.finish()
        return report

    # ------------------------------------------------------------------ #
    def _probe_sni(self, ip: str, sni: str) -> str:
        """
        Handshake with ``ip`` presenting ``sni``. Returns one of:
        ok / reset / eof / timeout / alert / error.
        Certificate checks are disabled on purpose: only the *behaviour*
        of the connection matters here, not who the server claims to be.
        """
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((ip, TLS_TEST_PORT), timeout=TLS_TIMEOUT) as sock:
                with context.wrap_socket(sock, server_hostname=sni):
                    return "ok"
        except ConnectionResetError:
            return "reset"
        except ssl.SSLEOFError:
            return "eof"          # peer closed mid-handshake, typical of an injected RST/FIN
        except ssl.SSLError:
            return "alert"        # the server itself answered with a TLS alert: not a block
        except (socket.timeout, TimeoutError):
            return "timeout"
        except OSError:
            return "error"

    def _sni_filtering_probe(self) -> CheckResult:
        """
        Contact ONE server IP with several different SNI names. If the
        handshake works for some names but is reset/dropped for others,
        the network is probably deciding by SNI, not by IP address.
        """
        self._report("Probing for SNI-based filtering ...")
        start = time.perf_counter()
        ips = resolve_host(SNI_PROBE_BASELINE_HOST, family=socket.AF_INET)
        if not ips:
            return CheckResult(
                name="SNI Filtering Probe",
                status=Status.UNKNOWN,
                message="Could not resolve the probe server, so SNI filtering could not be tested.",
            )

        ip = ips[0]
        outcomes = {sni: self._probe_sni(ip, sni) for sni in SNI_PROBE_NAMES}
        duration_ms = (time.perf_counter() - start) * 1000.0

        good = {"ok", "alert"}   # the server answered, so the path is not blocking this name
        bad = {"reset", "eof", "timeout"}
        passed = [s for s, o in outcomes.items() if o in good]
        blocked = [s for s, o in outcomes.items() if o in bad]
        details = {"server_ip": ip, "outcomes": outcomes, "suspected": False}

        if blocked and passed:
            details["suspected"] = True
            return CheckResult(
                name="SNI Filtering Probe",
                status=Status.WARNING,
                message=(
                    "Same server, different outcomes: handshakes were cut for "
                    + ", ".join(blocked) + " but worked for " + ", ".join(passed)
                    + ". This pattern is consistent with SNI-based filtering, though it is "
                    "not proof."
                ),
                details=details,
                duration_ms=duration_ms,
            )
        if blocked and not passed:
            return CheckResult(
                name="SNI Filtering Probe",
                status=Status.FAILED,
                message=(
                    f"Every handshake to {ip} failed regardless of SNI name, so this looks "
                    "like a general block of that address or of TLS, not SNI filtering."
                ),
                details=details,
                duration_ms=duration_ms,
            )
        if not passed:
            # Nothing succeeded and nothing was clearly cut (e.g. generic socket
            # errors): "no difference" would be a false all-clear.
            return CheckResult(
                name="SNI Filtering Probe",
                status=Status.UNKNOWN,
                message="No handshake could be completed for any name, so SNI filtering "
                        "could not be assessed.",
                details=details,
                duration_ms=duration_ms,
            )
        return CheckResult(
            name="SNI Filtering Probe",
            status=Status.OK,
            message="Handshakes behaved the same for every SNI name tested.",
            details=details,
            duration_ms=duration_ms,
        )
