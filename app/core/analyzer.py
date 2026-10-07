"""
analyzer.py
===========
Takes every :class:`ModuleReport` produced by the test modules and the
:class:`NetworkInfo` snapshot, and produces a list of plain-language,
*probabilistic* interpretations for an ordinary user.

Hard rule: this module NEVER states a definitive censorship claim. It
only ever uses hedged language such as "may", "appears to", "could
indicate" - because a single client-side test can never prove intent or
certainty about network policy.
"""

from __future__ import annotations

from app.core.network_info import IP_STATE_NO_INTERNET
from app.diag import correlation
from app.diag.correlation import DiagnosticSummary, OverallStatus
from app.diag.reportlayers import collect_results
from app.diag.results import Severity
from app.logger import get_logger
from app.models import CheckResult, Interpretation, ModuleReport, NetworkInfo, Status

log = get_logger(__name__)


_SEVERITY_TO_STATUS = {
    Severity.CRITICAL: Status.FAILED, Severity.ERROR: Status.FAILED, Severity.WARNING: Status.WARNING,
    Severity.INFO: Status.OK, Severity.OK: Status.OK, Severity.SKIPPED: Status.OK,
}
_OVERALL_TO_STATUS = {
    OverallStatus.HEALTHY: Status.OK, OverallStatus.DEGRADED: Status.WARNING,
    OverallStatus.DISRUPTED: Status.FAILED, OverallStatus.INCONCLUSIVE: Status.UNKNOWN,
}


def _dedupe(items: list[Interpretation]) -> list[Interpretation]:
    seen: set[str] = set()
    out: list[Interpretation] = []
    for item in items:
        if item.text not in seen:
            seen.add(item.text)
            out.append(item)
    return out


class ResultAnalyzer:
    """
    Two cooperating layers:

    * the correlation engine (``app.diag.correlation``) looks at every normalized result at once and
      produces confidence-rated diagnoses - this is the authority on root causes;
    * the legacy module-specific summaries below add detail lines. They are suppressed when the
      correlation engine already concluded that the Internet is unavailable, so that a pile of
      secondary failures is never listed as separate problems.
    """

    last_summary: DiagnosticSummary | None = None

    def analyze(self, network_info: NetworkInfo, modules: list[ModuleReport]) -> list[Interpretation]:
        return self.analyze_full(network_info, modules)[0]

    def analyze_full(self, network_info: NetworkInfo,
                     modules: list[ModuleReport]) -> tuple[list[Interpretation], DiagnosticSummary]:
        summary = correlation.analyze(collect_results(modules, network_info))
        self.last_summary = summary
        by_name = {m.module_name: m for m in modules}
        interpretations: list[Interpretation] = []

        interpretations.append(Interpretation(summary.headline, _OVERALL_TO_STATUS[summary.overall]))
        for diag in summary.diagnoses:
            # One line per fact, so that every line can be translated on its own.
            lines = [diag.headline]
            lines += [f"Evidence: {e.rstrip('.')}" if not e.endswith("...") else f"Evidence: {e}"
                      for e in diag.evidence[:3]]
            if diag.possible_causes:
                lines.append("Possible causes: " + "; ".join(diag.possible_causes[:4]))
            if diag.caveats:
                lines.append(f"Note: {diag.caveats[0]}")
            interpretations.append(Interpretation("\n".join(lines),
                                                  _SEVERITY_TO_STATUS.get(diag.severity, Status.WARNING)))

        covered = {d.diagnosis_id for d in summary.diagnoses}
        if summary.overall is not OverallStatus.DISRUPTED:
            for summarize in (self._dns_summary, self._tcp_summary, self._udp_summary, self._tls_summary,
                              self._http_summary, self._protocol_summary, self._latency_summary,
                              self._mtu_summary, self._sni_summary, self._behavior_summary,
                              self._advanced_signals):
                # The correlation engine already explained these; do not say it twice in other words.
                if summarize in (self._dns_summary,) and covered & {"dns_interference", "dns_failure"}:
                    continue
                if summarize in (self._sni_summary,) and "sni_filtering" in covered:
                    continue
                interpretations.extend(summarize(by_name))
            interpretations.extend(self._ip_version_summary(network_info))
            interpretations.extend(self._positive_summary(by_name))
        if not covered & {"vpn_detected", "proxy_detected"}:
            interpretations.extend(self._environment_signals(by_name))
        else:
            interpretations.extend(self._environment_signals(by_name, proxy_vpn=False))
        return _dedupe(interpretations), summary

    # ------------------------------------------------------------------ #
    def _find(self, module: ModuleReport | None, name_substring: str) -> CheckResult | None:
        if module is None:
            return None
        for check in module.checks:
            if name_substring.lower() in check.name.lower():
                return check
        return None

    def _basic_summary(self, info: NetworkInfo, by_name: dict[str, ModuleReport]) -> list[Interpretation]:
        out: list[Interpretation] = []
        if info.internet_reachable:
            out.append(Interpretation("Internet connectivity is available on this machine.", Status.OK))
        else:
            out.append(Interpretation(
                "No Internet connectivity could be confirmed at all. Check your cable/Wi-Fi, "
                "router, and modem before investigating anything else.",
                Status.FAILED,
            ))
        return out

    def _dns_summary(self, by_name: dict[str, ModuleReport]) -> list[Interpretation]:
        out: list[Interpretation] = []
        module = by_name.get("DNS Test")
        if not module:
            return out

        comparison = self._find(module, "DNS Answer Comparison")
        if comparison and comparison.status == Status.FAILED:
            out.append(Interpretation(
                "One or more DNS resolvers returned a known block-page style address. "
                "This strongly suggests DNS-based filtering or DNS poisoning is affecting "
                "this network.",
                Status.FAILED,
            ))
        elif comparison and comparison.status == Status.WARNING:
            out.append(Interpretation(
                "Different public DNS resolvers returned inconsistent results for well known "
                "domains. This could indicate DNS interference, but may also be normal CDN "
                "behaviour - treat as a possible signal, not proof.",
                Status.WARNING,
            ))

        failed_resolvers = [
            c for c in module.checks
            if c.status == Status.FAILED and "resolve via" in c.name.lower()
        ]
        if failed_resolvers:
            names = ", ".join(c.name for c in failed_resolvers)
            out.append(Interpretation(
                f"The following DNS resolvers could not be reached at all: {names}. "
                "The network may be blocking outbound DNS queries to non-default servers.",
                Status.WARNING,
            ))

        return out

    def _tcp_summary(self, by_name: dict[str, ModuleReport]) -> list[Interpretation]:
        out: list[Interpretation] = []
        module = by_name.get("TCP Port Scanner")
        if not module:
            return out

        port_443 = self._find(module, "TCP 443")
        if port_443 and port_443.status != Status.OK:
            out.append(Interpretation(
                "TCP port 443 (standard HTTPS) does not appear reachable in the port scan. "
                "This may indicate that HTTPS traffic is being blocked on this network.",
                Status.FAILED,
            ))

        reset_ports = [c for c in module.checks if "RESET" in c.message]
        if reset_ports:
            names = ", ".join(c.name for c in reset_ports)
            out.append(Interpretation(
                f"Connections to {names} were actively reset rather than timing out. "
                "An active reset (rather than silence) often indicates a firewall or "
                "middlebox is specifically intercepting this traffic, rather than a simple "
                "routing failure.",
                Status.WARNING,
            ))

        return out

    def _udp_summary(self, by_name: dict[str, ModuleReport]) -> list[Interpretation]:
        out: list[Interpretation] = []
        module = by_name.get("UDP Test")
        if not module:
            return out

        udp_443 = self._find(module, "UDP 443")
        if udp_443 and udp_443.status == Status.FAILED:
            out.append(Interpretation(
                "UDP port 443 (used by QUIC / HTTP-3) appears actively blocked "
                "(ICMP rejection received). The network may restrict UDP-based protocols.",
                Status.WARNING,
            ))

        return out

    def _tls_summary(self, by_name: dict[str, ModuleReport]) -> list[Interpretation]:
        out: list[Interpretation] = []
        module = by_name.get("TLS Test")
        if not module:
            return out

        tls13_failures = [c for c in module.checks if "TLS 1.3" in c.name and c.status != Status.OK]
        tls12_failures = [c for c in module.checks if "TLS 1.2" in c.name and c.status != Status.OK]

        if tls13_failures and not tls12_failures:
            out.append(Interpretation(
                "TLS 1.3 handshakes failed while TLS 1.2 succeeded. Some filtering systems "
                "specifically target newer TLS versions or ClientHello fingerprints - this "
                "pattern can be a sign of that, though it may also be an unrelated server issue.",
                Status.WARNING,
            ))
        elif tls13_failures and tls12_failures:
            out.append(Interpretation(
                "TLS handshakes failed for both TLS 1.2 and TLS 1.3 to the same host(s). "
                "This suggests a broader TLS/HTTPS connectivity problem rather than "
                "version-specific filtering.",
                Status.FAILED,
            ))

        cert_failures = [c for c in module.checks if "Certificate Validation" in c.name and c.status == Status.FAILED]
        if cert_failures:
            out.append(Interpretation(
                "Certificate validation could not be completed for one or more hosts. This "
                "can happen with interception proxies (including some antivirus/firewall "
                "software), captive portals, or genuine connectivity failures.",
                Status.WARNING,
            ))

        return out

    def _http_summary(self, by_name: dict[str, ModuleReport]) -> list[Interpretation]:
        out: list[Interpretation] = []
        module = by_name.get("HTTP Test")
        if not module:
            return out

        http3 = self._find(module, "HTTP/3")
        if http3 and http3.status in (Status.WARNING, Status.UNKNOWN):
            out.append(Interpretation(
                "HTTP/3 (QUIC) does not appear to be working on this network, even though "
                "the target server supports it. UDP-based HTTP/3 traffic may be restricted.",
                Status.WARNING,
            ))

        http2 = self._find(module, "HTTP/2")
        if http2 and http2.status == Status.WARNING:
            out.append(Interpretation(
                "The server did not negotiate HTTP/2 even though it normally supports it. "
                "This can indicate that something on the network path is interfering with "
                "the TLS ALPN negotiation.",
                Status.WARNING,
            ))

        return out

    def _protocol_summary(self, by_name: dict[str, ModuleReport]) -> list[Interpretation]:
        out: list[Interpretation] = []
        module = by_name.get("Protocol Tests")
        if not module:
            return out

        doh_failures = [c for c in module.checks if "DNS-over-HTTPS" in c.name and c.status == Status.FAILED]
        dot_failures = [c for c in module.checks if "DNS-over-TLS" in c.name and c.status == Status.FAILED]

        if doh_failures and dot_failures:
            out.append(Interpretation(
                "Both DNS-over-HTTPS and DNS-over-TLS failed. The network may be blocking "
                "encrypted DNS protocols specifically, forcing reliance on plain-text DNS "
                "(which is easier to monitor or filter).",
                Status.WARNING,
            ))
        elif doh_failures:
            out.append(Interpretation(
                "DNS-over-HTTPS failed for the tested provider(s), while other DNS paths "
                "may still work. This could indicate targeted blocking of DoH endpoints.",
                Status.WARNING,
            ))
        elif dot_failures:
            out.append(Interpretation(
                "DNS-over-TLS (port 853) failed for the tested provider(s). Some networks "
                "block this specific port since it is exclusively used for encrypted DNS.",
                Status.WARNING,
            ))

        icmp = self._find(module, "ICMP Echo")
        if icmp and icmp.status == Status.WARNING:
            out.append(Interpretation(
                "ICMP echo (ping) requests are not being answered. This is very commonly a "
                "normal firewall configuration and is not by itself a strong censorship signal.",
                Status.WARNING,
            ))

        return out

    def _latency_summary(self, by_name: dict[str, ModuleReport]) -> list[Interpretation]:
        out: list[Interpretation] = []
        module = by_name.get("Latency Test")
        if not module:
            return out

        high_latency = [c for c in module.checks if c.details.get("average_ms", 0) and c.details["average_ms"] > 250]
        if high_latency:
            names = ", ".join(c.name for c in high_latency)
            out.append(Interpretation(
                f"Notably high average latency was measured for: {names}. This can be caused "
                "by traffic being routed through additional inspection points, or simply by "
                "distance/ISP routing - both are possible explanations.",
                Status.WARNING,
            ))

        lossy = [c for c in module.checks if c.details.get("loss_percent", 0) and c.details["loss_percent"] > 10]
        if lossy:
            names = ", ".join(c.name for c in lossy)
            out.append(Interpretation(
                f"Significant packet loss was measured for: {names}. This usually points to "
                "a congested or unstable link rather than deliberate blocking.",
                Status.WARNING,
            ))

        return out

    def _mtu_summary(self, by_name: dict[str, ModuleReport]) -> list[Interpretation]:
        out: list[Interpretation] = []
        module = by_name.get("MTU Test")
        if not module:
            return out

        mtu_check = self._find(module, "Path MTU")
        if mtu_check and mtu_check.status == Status.WARNING:
            estimated = mtu_check.details.get("estimated_mtu")
            out.append(Interpretation(
                f"The estimated path MTU ({estimated} bytes) is below the standard 1500 bytes. "
                "This can cause intermittent failures or slowness for larger packets/connections, "
                "particularly with VPNs or tunnelled traffic.",
                Status.WARNING,
            ))

        return out

    def _sni_summary(self, by_name: dict[str, ModuleReport]) -> list[Interpretation]:
        out: list[Interpretation] = []
        probe = self._find(by_name.get("TLS Test"), "SNI Filtering Probe")
        if probe is None:
            return out
        if probe.details.get("suspected"):
            out.append(Interpretation(
                "TLS handshakes to the same server were cut for some website names but not "
                "for others. This pattern is consistent with SNI-based filtering, where the "
                "network inspects the name in the handshake. It may also have other causes, "
                "so treat it as a possibility rather than a conclusion.",
                Status.WARNING,
            ))
        elif probe.status == Status.OK:
            out.append(Interpretation(
                "No sign of SNI-based filtering: TLS handshakes behaved the same for every "
                "name tested.",
                Status.OK,
            ))
        return out

    def _behavior_summary(self, by_name: dict[str, ModuleReport]) -> list[Interpretation]:
        """Looks at HOW connections fail (silence vs. active reset), not only that they fail."""
        out: list[Interpretation] = []
        tcp = by_name.get("TCP Port Scanner")
        if tcp is None:
            return out

        states = {c.details.get("port"): c.details.get("state") for c in tcp.checks}
        timeouts = sorted(p for p, s in states.items() if s == "timeout")
        resets = sorted(p for p, s in states.items() if s == "reset")
        open_ports = sorted(p for p, s in states.items() if s == "open")

        if timeouts and open_ports:
            shown = ", ".join(str(p) for p in timeouts[:8])
            out.append(Interpretation(
                f"Some TCP ports ({shown}) time out while others such as "
                f"{', '.join(str(p) for p in open_ports[:3])} connect normally. Packets to "
                "those ports may be silently dropped by a firewall on this network, "
                "although the remote server could also simply not listen there.",
                Status.WARNING,
            ))
        if resets and open_ports:
            out.append(Interpretation(
                "Connections to some ports were actively reset while others succeeded, which "
                "can indicate a device on the path rejecting that specific traffic.",
                Status.WARNING,
            ))
        if not open_ports and states:
            out.append(Interpretation(
                "None of the tested TCP ports connected. This usually means a general "
                "connectivity problem or a network that blocks outgoing connections.",
                Status.FAILED,
            ))
        return out

    def _advanced_signals(self, by_name: dict[str, ModuleReport]) -> list[Interpretation]:
        """TCP stall, per-site layer failures, block pages, and TCP-ok/TLS-fail patterns."""
        out: list[Interpretation] = []

        stall = self._find(by_name.get("TCP Stall Test"), "TCP Stall")
        if stall is not None and stall.details.get("suspected"):
            out.append(Interpretation(
                "A download started normally but stopped after roughly 10-40 KB. Some "
                "filtering systems behave this way for certain hosting providers. A weak or "
                "unstable connection can look the same, so this is a possibility only.",
                Status.WARNING,
            ))

        sites = by_name.get("Website Reachability")
        summary = self._find(sites, "Control vs Test")
        if summary is not None and summary.status == Status.WARNING:
            stages = summary.details.get("failed_stages", {})
            meaning = {
                "dns": "name resolution (the DNS answer was missing or looked tampered with)",
                "tcp": "the TCP connection (packets dropped or reset before any handshake)",
                "tls": "the TLS handshake (TCP worked, but the encrypted handshake was cut - "
                       "consistent with the network looking at the site name)",
                "http": "the HTTPS request (a block page or error status)",
            }
            where = "; ".join(meaning.get(s, s) for s in sorted(stages))
            out.append(Interpretation(
                f"Some test websites failed while the control sites worked. The failures "
                f"happened at: {where}. This suggests restrictions specific to those sites, "
                "but it cannot prove who or what causes them.",
                Status.WARNING,
            ))
        elif summary is not None and summary.status == Status.FAILED:
            out.append(Interpretation(
                "The control websites also failed, so per-site results are not reliable. "
                "Fix the general connection first.",
                Status.FAILED,
            ))

        block = self._find(by_name.get("HTTP Test"), "Block Page")
        if block is not None and block.details.get("suspected"):
            out.append(Interpretation(
                "The plain HTTP response contained signs of a block page "
                "(e.g. status 451 or a redirect to a private address).",
                Status.FAILED,
            ))

        tls = by_name.get("TLS Test")
        if tls is not None:
            tcp_ok_tls_failed = [
                c for c in tls.checks
                if "Handshake" in c.name and c.status != Status.OK
                and c.details.get("tcp_connected")
            ]
            if tcp_ok_tls_failed:
                out.append(Interpretation(
                    "TCP connections succeeded but TLS handshakes failed on the same host. "
                    "That points at the encrypted handshake itself (for example a device "
                    "inspecting the ClientHello) rather than at the address being unreachable. "
                    "A server-side or software issue can look the same.",
                    Status.WARNING,
                ))
        return out

    def _environment_signals(self, by_name: dict[str, ModuleReport], proxy_vpn: bool = True) -> list[Interpretation]:
        out: list[Interpretation] = []

        env = by_name.get("Proxy & VPN Detection")
        if proxy_vpn and env is not None and any(c.details.get("suspected") for c in env.checks):
            out.append(Interpretation(
                "A proxy or VPN/tunnel may be active on this computer. If it is, every test "
                "here measured that tunnel rather than your direct Internet connection, so "
                "the other results should be read with that in mind. Disconnect it and run "
                "the diagnostics again to see your real connection.",
                Status.WARNING,
            ))

        probe = self._find(by_name.get("Protocol Whitelist Probe"), "Protocol Whitelist")
        if probe is not None and probe.details.get("suspected"):
            out.append(Interpretation(
                "Unusual traffic on port 443 got no reaction while the same traffic on another "
                "port did. That is the pattern of a filter allowing only recognisable "
                "protocols on standard ports. Other explanations exist, so this is a "
                "possibility rather than a conclusion.",
                Status.WARNING,
            ))
        return out

    def _positive_summary(self, by_name: dict[str, ModuleReport]) -> list[Interpretation]:
        """Confirms what IS working, so the user sees the whole picture."""
        out: list[Interpretation] = []

        dns = by_name.get("DNS Test")
        if dns is not None:
            resolved_ok = [c for c in dns.checks if "resolve via" in c.name.lower()
                           and c.status == Status.OK]
            if resolved_ok:
                out.append(Interpretation(
                    f"DNS resolution is working ({len(resolved_ok)} resolver(s) answered "
                    "all test domains).", Status.OK))

        tls = by_name.get("TLS Test")
        if tls is not None and any(
            c.status == Status.OK and "Handshake" in c.name for c in tls.checks
        ):
            out.append(Interpretation("At least one TLS handshake completed successfully.", Status.OK))

        http = by_name.get("HTTP Test")
        http2 = self._find(http, "HTTP/2")
        if http2 is not None and http2.status == Status.OK:
            out.append(Interpretation("HTTP/2 negotiated successfully.", Status.OK))
        return out

    def _ip_version_summary(self, info: NetworkInfo) -> list[Interpretation]:
        out: list[Interpretation] = []
        if info.ipv6_state == IP_STATE_NO_INTERNET:
            out.append(Interpretation(
                "IPv6 is configured on this computer, but connections to external IPv6 hosts "
                "failed. Programs that prefer IPv6 may be slow to fall back to IPv4; the router or "
                "ISP may not provide working IPv6.",
                Status.WARNING,
            ))
        elif not info.ipv6_available:
            out.append(Interpretation(
                "IPv6 connectivity is unavailable on this network. This is common and usually "
                "not an issue by itself, since most services still work fine over IPv4.",
                Status.WARNING,
            ))
        if not info.ipv4_available:
            out.append(Interpretation(
                "IPv4 connectivity is unavailable, which is unusual and likely indicates a "
                "serious connectivity problem.",
                Status.FAILED,
            ))
        return out
