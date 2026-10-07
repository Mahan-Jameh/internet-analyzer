"""
correlation.py
==============
The root-cause (correlation) engine. It looks at *all* normalized results
together and produces :class:`Diagnosis` objects: inferred conclusions that
carry evidence, a confidence score derived from that evidence, and the list of
tests they explain. It never states certainty it does not have.

Wording ladder (fixed by confidence, not by the rule author):

    measured fact ........ "Detected"
    confidence >= 0.75 ... "Likely"
    confidence >= 0.40 ... "Possible"
    otherwise ............ "Inconclusive"

Results are located by ``category`` (and a few ``metadata['role']`` values),
never by name substrings, so renaming a test cannot silently break a rule.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Iterable

from app.diag.results import Severity, TechnicalStatus, TestResult

_S = TechnicalStatus

# A result in one of these states says something definite about reachability.
FAIL_STATUSES = frozenset({
    _S.TIMEOUT, _S.UNREACHABLE, _S.RESET, _S.DNS_FAILED, _S.TLS_FAILED,
    _S.HTTP_FAILED, _S.BLOCKED, _S.FILTERED, _S.REFUSED,
})
# These say nothing about the network (local error, no verdict, not run).
NO_SIGNAL = frozenset({
    _S.ERROR, _S.UNKNOWN, _S.INCONCLUSIVE, _S.SKIPPED, _S.NOT_APPLICABLE, _S.OPEN_OR_FILTERED,
})

# HTTP checks that are optional extras: their failure says nothing about basic HTTPS reachability.
OPTIONAL_HTTP_ROLES = frozenset({"http3", "compression", "keepalive", "block_page", "layer_dependent"})
HIGH_LATENCY_MS = 250.0
HIGH_LOSS_PERCENT = 10.0
NORMAL_MTU = 1500


class OverallStatus(str, Enum):
    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    DISRUPTED = "DISRUPTED"        # the Internet appears unavailable
    INCONCLUSIVE = "INCONCLUSIVE"


def confidence_level(confidence: float) -> str:
    return "HIGH" if confidence >= 0.7 else "MEDIUM" if confidence >= 0.4 else "LOW"


def wording_for(confidence: float, measured: bool = False) -> str:
    if measured:
        return "Detected"
    if confidence >= 0.75:
        return "Likely"
    if confidence >= 0.40:
        return "Possible"
    return "Inconclusive"


def clamp_confidence(value: float) -> float:
    return round(min(0.95, max(0.05, value)), 2)


@dataclass
class Diagnosis:
    diagnosis_id: str
    title: str                                  # without the wording prefix
    severity: Severity
    confidence: float
    layer: str                                  # dns / tcp / tls / http / icmp / ipv6 / local ...
    evidence: list[str] = field(default_factory=list)
    possible_causes: list[str] = field(default_factory=list)
    affected_tests: list[str] = field(default_factory=list)
    caveats: list[str] = field(default_factory=list)
    measured: bool = False                      # a directly observed fact, not an inference

    @property
    def wording(self) -> str:
        return wording_for(self.confidence, self.measured)

    @property
    def level(self) -> str:
        return confidence_level(self.confidence)

    @property
    def headline(self) -> str:
        return f"{self.wording}: {self.title}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.diagnosis_id, "title": self.title, "headline": self.headline,
            "severity": self.severity.value, "confidence": self.confidence,
            "confidence_level": self.level, "wording": self.wording, "layer": self.layer,
            "evidence": self.evidence, "possible_causes": self.possible_causes,
            "affected_tests": self.affected_tests, "caveats": self.caveats,
            "measured": self.measured,
        }


@dataclass
class Finding:
    """One line of the 'key findings' layer: a tick, a warning or a cross."""

    symbol: str         # "ok" | "warn" | "fail" | "info"
    text: str

    def to_dict(self) -> dict[str, str]:
        return {"symbol": self.symbol, "text": self.text}


@dataclass
class DiagnosticSummary:
    overall: OverallStatus
    headline: str
    findings: list[Finding] = field(default_factory=list)
    diagnoses: list[Diagnosis] = field(default_factory=list)
    blocked: list[dict[str, Any]] = field(default_factory=list)
    stats: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "overall_status": self.overall.value,
            "headline": self.headline,
            "findings": [f.to_dict() for f in self.findings],
            "diagnoses": [d.to_dict() for d in self.diagnoses],
            "blocked_tests": self.blocked,
            "stats": self.stats,
        }


# --------------------------------------------------------------------------
# Result access helpers
# --------------------------------------------------------------------------
class ResultSet:
    def __init__(self, results: Iterable[TestResult]) -> None:
        self.all: list[TestResult] = list(results)

    def cat(self, *cats: str) -> list[TestResult]:
        return [r for r in self.all if r.category in cats and not r.skipped]

    def role(self, category: str, role: str) -> list[TestResult]:
        return [r for r in self.cat(category) if r.metadata.get("role") == role]

    @staticmethod
    def good(rs: Iterable[TestResult]) -> list[TestResult]:
        return [r for r in rs if r.ok]

    @staticmethod
    def bad(rs: Iterable[TestResult]) -> list[TestResult]:
        return [r for r in rs if r.status in FAIL_STATUSES]

    def tcp_reach(self, ports: tuple[int, ...] = (80, 443)) -> list[TestResult]:
        """TCP results meant to answer 'can I reach this host', not 'what is open'."""
        return [r for r in self.cat("tcp")
                if r.port in ports and r.metadata.get("role", "reachability") == "reachability"]

    def first(self, test_id: str) -> TestResult | None:
        return next((r for r in self.all if r.test_id == test_id), None)

    def ids(self, rs: Iterable[TestResult]) -> list[str]:
        return [r.test_id for r in rs]


def _label(r: TestResult) -> str:
    port = f":{r.port}" if r.port else ""
    return f"{r.target or r.test_id}{port}"


def _facts(prefix: str, rs: list[TestResult], limit: int = 4) -> str:
    labels = list(dict.fromkeys(_label(r) for r in rs))          # one entry per target
    names = ", ".join(labels[:limit])
    more = f" (+{len(labels) - limit} more)" if len(labels) > limit else ""
    return f"{prefix}: {names}{more}"


# --------------------------------------------------------------------------
# Rules. Each returns zero or more Diagnosis objects.
# --------------------------------------------------------------------------
def _ip_level_ok(rs: ResultSet) -> list[TestResult]:
    """Evidence that packets reach the Internet without needing DNS."""
    ip_tcp = [r for r in rs.tcp_reach() if r.metadata.get("target_is_ip")]
    return [*rs.good(ip_tcp), *rs.good(rs.cat("icmp")), *rs.good(rs.cat("ip_family"))]


def rule_internet_unavailable(rs: ResultSet) -> list[Diagnosis]:
    external = [*rs.cat("tcp", "icmp", "http", "tls", "dns_resolution", "ip_family")]
    signal = [r for r in external if r.status not in NO_SIGNAL]
    if len(signal) < 3 or rs.good(signal):
        return []
    gw = rs.first("gateway")
    evidence = [f"No external probe succeeded ({len(signal)} probes with a definite result)."]
    conf = 0.7
    causes = ["Local network/Wi-Fi/cable problem", "ISP outage", "Router or modem not connected upstream"]
    if gw is not None and gw.status in FAIL_STATUSES:
        evidence.append("The local gateway also did not respond.")
        conf += 0.15
        title = "Local network problem: the gateway and all external targets are unreachable"
        layer = "local"
    else:
        title = "Internet appears unavailable: every external probe failed"
        layer = "routing"
        if gw is not None and gw.ok:
            evidence.append("The local gateway responds, so the problem is likely beyond your router.")
    return [Diagnosis("internet_unavailable", title, Severity.CRITICAL, clamp_confidence(conf), layer,
                      evidence, causes, rs.ids(signal))]


def rule_dns(rs: ResultSet) -> list[Diagnosis]:
    system = rs.role("dns_resolution", "system")
    direct = rs.role("dns_resolution", "direct")
    ip_ok = _ip_level_ok(rs)
    sys_bad = rs.bad(system)
    out: list[Diagnosis] = []
    domains_failed = {r.metadata.get("domain") or r.target for r in sys_bad}
    if len(domains_failed) >= 2 and not rs.good(system):          # not a single-hostname failure
        evidence = [f"The system resolver failed for {len(domains_failed)} different names."]
        conf = 0.6
        if ip_ok:
            evidence.append("IP-level connectivity works, so the Internet itself is reachable.")
            conf += 0.15
        if rs.good(direct):
            evidence.append(_facts("Direct queries to public resolvers succeeded", rs.good(direct), 3))
            conf += 0.1
            title = "The system's DNS resolver is failing while public resolvers answer"
            causes = ["ISP/router DNS server problem", "DNS filtering of the configured resolver"]
        else:
            title = "DNS resolution is failing"
            causes = ["Configured DNS server unreachable or broken", "DNS filtering or interference"]
        out.append(Diagnosis("dns_failure", title, Severity.ERROR, clamp_confidence(conf), "dns",
                             evidence, causes, rs.ids(sys_bad)))
    # Different resolvers disagree -> possible interference (needs the DNS module's own outlier flag)
    outliers = [r for r in rs.cat("dns_resolution") if r.metadata.get("outlier")]
    if outliers:
        out.append(Diagnosis(
            "dns_interference", "DNS answers differ between resolvers (possible DNS interference)",
            Severity.WARNING, clamp_confidence(0.55 + 0.1 * min(len(outliers) - 1, 2)), "dns",
            [_facts("Resolvers returning an outlying answer", outliers, 3)],
            ["DNS filtering/poisoning", "CDN or geo-based answers (a normal cause)"],
            rs.ids(outliers),
            ["Different answers are common for CDN-hosted sites, so this is only a hint."]))
    return out


def rule_tcp_filtering(rs: ResultSet) -> list[Diagnosis]:
    reach = rs.tcp_reach()
    bad = [r for r in reach if r.status in (_S.TIMEOUT, _S.UNREACHABLE)]
    if not bad or rs.good(reach):
        return []
    dns_ok = rs.good(rs.cat("dns_resolution")) or all(r.metadata.get("target_is_ip") for r in bad)
    if not dns_ok:
        return []
    ports = {r.port for r in bad}
    if not {80, 443} <= ports and len(bad) < 2:
        return []
    evidence = [_facts("TCP connection did not complete", bad)]
    conf = 0.5
    if rs.good(rs.cat("icmp")):
        evidence.append("ICMP echo works, so the host/path is up but TCP is not getting through.")
        conf += 0.2
    if any(r.retry_outcome.value == "persistent_failure" for r in bad):
        evidence.append("The failure repeated on retry.")
        conf += 0.1
    return [Diagnosis(
        "tcp_filtering", "TCP connections are failing (firewall, filtering or routing issue)",
        Severity.ERROR, clamp_confidence(conf), "tcp", evidence,
        ["Firewall or ISP filtering of these ports", "Routing problem towards the target",
         "Remote host not accepting connections", "Packet loss"], rs.ids(bad),
        ["A timeout is not proof that the port is closed or filtered."])]


def rule_tls(rs: ResultSet) -> list[Diagnosis]:
    handshakes = [r for r in rs.cat("tls") if r.metadata.get("role", "handshake") == "handshake"]
    tcp_ok_hosts = {r.target for r in rs.good(rs.cat("tcp")) if r.port == 443}
    bad = [r for r in handshakes
           if r.status in (_S.TLS_FAILED, _S.TIMEOUT, _S.RESET)
           and r.error_code != "CERTIFICATE_ERROR"
           and (r.target in tcp_ok_hosts or r.metadata.get("tcp_ok"))]
    out: list[Diagnosis] = []
    if bad and not rs.good(handshakes):
        evidence = ["DNS and TCP/443 succeeded for these targets.", _facts("TLS handshake failed", bad)]
        conf = 0.55
        http_bad = rs.bad([r for r in rs.cat("http")
                           if r.metadata.get("role") not in OPTIONAL_HTTP_ROLES])
        if http_bad:
            evidence.append("HTTPS requests failed as well, which is consistent with a TLS-level problem.")
            conf += 0.15
        if any(r.retry_outcome.value == "persistent_failure" for r in bad):
            evidence.append("The handshake failed on every attempt.")
            conf += 0.1
        out.append(Diagnosis(
            "tls_failure", "TLS connectivity problem (TCP works, the TLS handshake does not)",
            Severity.ERROR, clamp_confidence(conf), "tls", evidence,
            ["TLS interception or filtering on the path", "TLS negotiation problem",
             "Server-side issue"], [*rs.ids(bad), *rs.ids(http_bad)]))
    # SNI comparison: same IP, handshake works without SNI / with another name but not with the target name
    sni = [r for r in rs.cat("tls") if r.metadata.get("role") == "sni_probe"]
    for r in sni:
        if r.interpretation == "SNI_SELECTIVE_FAILURE":
            conf = 0.7 + (0.1 if r.retry_outcome.value == "persistent_failure" else 0.0)
            out.append(Diagnosis(
                "sni_filtering", "Filtering that depends on the TLS server name (SNI)",
                Severity.WARNING, clamp_confidence(conf), "tls", [*[e.text for e in r.evidence]],
                ["SNI-based filtering", "A server that rejects unknown names (less likely)"],
                [r.test_id], ["This comparison is evidence, not proof."]))
    return out


def rule_icmp_only(rs: ResultSet) -> list[Diagnosis]:
    icmp = rs.cat("icmp")
    if not icmp or rs.good(icmp):
        return []
    reachable = rs.good(rs.tcp_reach(ports=(443, 80, 53))) or rs.good(rs.cat("http"))
    if not reachable:
        return []
    return [Diagnosis(
        "icmp_blocked", "ICMP echo (ping) is blocked or unavailable; Internet connectivity appears functional",
        Severity.INFO, 0.8, "icmp",
        [_facts("Ping failed", rs.bad(icmp) or icmp, 3), "TCP or HTTPS connections succeeded."],
        ["Firewall dropping ICMP", "Target does not answer ping"], rs.ids(icmp),
        ["Ping failure alone does not mean the Internet is down."])]


def rule_ipv6(rs: ResultSet) -> list[Diagnosis]:
    v4 = next((r for r in rs.cat("ip_family") if r.address_family == "IPv4"), None)
    v6 = next((r for r in rs.cat("ip_family") if r.address_family == "IPv6"), None)
    if v6 is None or v4 is None or not v4.ok:
        return []
    if v6.metrics.get("configured") is False:
        return [Diagnosis("ipv6_not_configured", "IPv6 is not configured on this connection (IPv4 works)",
                          Severity.INFO, 0.9, "ipv6",
                          ["No usable global IPv6 address or route was found."], [], [v6.test_id],
                          measured=True)]
    if v6.status in FAIL_STATUSES:
        return [Diagnosis(
            "ipv6_broken", "IPv6 appears configured but does not reach the Internet while IPv4 works",
            Severity.WARNING, clamp_confidence(0.65 + (0.1 if v6.metrics.get("default_route") else 0)), "ipv6",
            ["IPv4 reaches the Internet.", "IPv6 is configured but external IPv6 probes failed."],
            ["ISP/router IPv6 misconfiguration", "IPv6 blocked upstream"], [v6.test_id],
            ["Browsers fall back to IPv4, so impact is often small."])]
    return []


def rule_quality(rs: ResultSet) -> list[Diagnosis]:
    lat = rs.cat("latency")
    tcp_open = rs.good(rs.tcp_reach(ports=(80, 443, 53)))
    bad = [r for r in lat if (r.metrics.get("packet_loss_percent") or 0) >= HIGH_LOSS_PERCENT
           or (r.metrics.get("average_ms") or 0) >= HIGH_LATENCY_MS]
    if not bad:
        return []
    evidence = [f"{_label(r)}: avg {r.metrics.get('average_ms')} ms, loss {r.metrics.get('packet_loss_percent')}%"
                for r in bad[:3]]
    conf = 0.6 + (0.1 if len(bad) >= 2 else 0) + (0.1 if tcp_open else 0)
    if tcp_open:
        evidence.append("TCP connections to the Internet succeed, so ports are reachable.")
    title = "Network quality is degraded (high latency or packet loss)"
    if tcp_open:
        title += "; this is not a port-availability problem"
    return [Diagnosis("quality_degraded", title, Severity.WARNING, clamp_confidence(conf), "quality",
                      evidence, ["Congested or weak Wi-Fi/link", "ISP congestion", "Overloaded device"],
                      rs.ids(bad))]


def rule_mtu(rs: ResultSet) -> list[Diagnosis]:
    out = []
    for r in rs.cat("mtu"):
        path = r.metrics.get("discovered_path_mtu")
        if path and path < NORMAL_MTU - 20:
            out.append(Diagnosis(
                "mtu_reduced", f"The path MTU is reduced ({path} bytes instead of {NORMAL_MTU})",
                Severity.INFO if path >= 1400 else Severity.WARNING, 0.45, "mtu",
                [f"Largest packet that passed: {r.metrics.get('largest_successful_packet')} bytes.",
                 f"Smallest packet that failed: {r.metrics.get('smallest_failed_packet')} bytes."],
                ["PPPoE, VPN or other encapsulation overhead", "A PMTUD problem (ICMP 'fragmentation needed' filtered)"],
                [r.test_id], ["Not a root cause by itself; a reduced MTU is common and often harmless."]))
    return out


def rule_environment(rs: ResultSet) -> list[Diagnosis]:
    out = []
    for r in rs.cat("vpn", "proxy"):
        kind = r.metadata.get("kind")
        if kind in ("virtual_adapter", "vpn_dns"):
            continue                       # supporting evidence only; a VM adapter is not a VPN
        if kind == "vpn_adapter" and not r.metrics.get("connected"):
            continue                       # installed but not connected: no routing influence
        if r.metadata.get("detected"):
            what = "VPN/tunnel adapter" if r.category == "vpn" else "Proxy"
            raw = r.metadata.get("detail") or r.summary
            detail = "; ".join(str(x) for x in raw) if isinstance(raw, (list, tuple)) else raw
            out.append(Diagnosis(
                f"{r.category}_detected", f"{what} detected; its routing may influence the results of other tests",
                Severity.INFO, 0.95, "environment", [str(detail)], [], [r.test_id],
                ["Detection is evidence about the environment, not a fault."], measured=True))
    return out


def rule_sites(rs: ResultSet) -> list[Diagnosis]:
    sites = rs.cat("site")
    controls = [r for r in sites if r.metadata.get("role") == "control"]
    tests = [r for r in sites if r.metadata.get("role") != "control"]
    if not controls or not rs.good(controls) or not tests:
        return []
    failing = [r for r in tests if r.status in FAIL_STATUSES or r.status is _S.PARTIAL]
    out = []
    by_layer: dict[str, list[TestResult]] = {}
    for r in failing:
        by_layer.setdefault(str(r.metadata.get("failed_layer") or "unknown"), []).append(r)
    names = {"dns": "name resolution (DNS)", "tcp": "the TCP connection", "tls": "the TLS handshake",
             "http": "the HTTP request"}
    for layer, items in by_layer.items():
        if layer == "unknown":
            continue
        conf = 0.5 + 0.1 * min(len(items) - 1, 3)
        out.append(Diagnosis(
            f"site_{layer}", f"Some sites fail at {names.get(layer, layer)} while control sites work",
            Severity.WARNING, clamp_confidence(conf), layer,
            [_facts("Failing sites", items, 5), _facts("Control sites that work", rs.good(controls), 3)],
            ["Site-specific blocking or filtering", "The site itself is down or rate-limiting"],
            rs.ids(items), ["A single failing site is weak evidence."]))
    return out


RULES: tuple[Callable[[ResultSet], list[Diagnosis]], ...] = (
    rule_internet_unavailable, rule_dns, rule_tcp_filtering, rule_tls, rule_icmp_only,
    rule_ipv6, rule_quality, rule_mtu, rule_sites, rule_environment,
)


# --------------------------------------------------------------------------
# Key findings, overall status
# --------------------------------------------------------------------------
_CATEGORY_LABELS = (
    ("gateway", "Local gateway"), ("dns_resolution", "DNS resolution"), ("tcp", "TCP connectivity"),
    ("tls", "TLS connectivity"), ("http", "HTTP/HTTPS"), ("icmp", "ICMP (ping)"),
    ("udp", "UDP probes"), ("latency", "Latency"),
)


def _category_finding(label: str, results: list[TestResult]) -> Finding | None:
    real = [r for r in results if not r.skipped and r.status not in NO_SIGNAL]
    if not real:
        return None
    good, bad = rs_count(real)
    if bad == 0:
        return Finding("ok", f"{label}: working")
    if good == 0:
        return Finding("fail", f"{label}: failing")
    return Finding("warn", f"{label}: partially working")


def rs_count(results: list[TestResult]) -> tuple[int, int]:
    return (sum(1 for r in results if r.ok), sum(1 for r in results if r.status in FAIL_STATUSES))


def _build_findings(rs: ResultSet) -> list[Finding]:
    findings: list[Finding] = []
    for category, label in _CATEGORY_LABELS:
        results = rs.cat(category)
        if category == "tcp":
            results = [r for r in results if r.metadata.get("role", "reachability") == "reachability"]
        f = _category_finding(label, results)
        if f:
            findings.append(f)
    for r in rs.cat("ip_family"):
        fam = r.address_family or "IP"
        if r.ok:
            findings.append(Finding("ok", f"{fam} connectivity: available"))
        elif r.metrics.get("configured") is False:
            findings.append(Finding("info", f"{fam}: not configured"))
        else:
            findings.append(Finding("fail" if r.status in FAIL_STATUSES else "info",
                                    f"{fam} connectivity: not working"))
    return findings


def analyze(results: Iterable[TestResult]) -> DiagnosticSummary:
    """Correlate every result of a run into one diagnostic summary."""
    rs = ResultSet(results)
    diagnoses: list[Diagnosis] = []
    for rule in RULES:
        try:
            diagnoses.extend(rule(rs))
        except Exception:  # noqa: BLE001 - one broken rule must not hide the others
            from app.logger import get_logger
            get_logger(__name__).exception("correlation rule %s failed", rule.__name__)

    sev_order = {Severity.CRITICAL: 0, Severity.ERROR: 1, Severity.WARNING: 2, Severity.INFO: 3,
                 Severity.OK: 4, Severity.SKIPPED: 5}
    diagnoses.sort(key=lambda d: (sev_order[d.severity], -d.confidence))

    # An outage explains every other failure - do not list those as separate problems.
    if any(d.diagnosis_id == "internet_unavailable" for d in diagnoses):
        diagnoses = [d for d in diagnoses if d.diagnosis_id in ("internet_unavailable", "vpn_detected", "proxy_detected")]

    findings = _build_findings(rs)
    blocked = [
        {"test_id": r.test_id, "blocked_by": r.metadata.get("blocked_by", []),
         "reason": r.metadata.get("skip_reason")}
        for r in rs.all if r.metadata.get("skip_reason") == "BLOCKED_BY_DEPENDENCY"
    ]
    signal = [r for r in rs.all if r.status not in NO_SIGNAL]
    stats = {"tests": len(rs.all), "with_signal": len(signal), "ok": len(rs.good(rs.all)),
             "failed": len(rs.bad(rs.all)), "skipped": sum(1 for r in rs.all if r.skipped)}

    actionable = [d for d in diagnoses if d.severity in (Severity.CRITICAL, Severity.ERROR, Severity.WARNING)]
    if any(d.diagnosis_id == "internet_unavailable" for d in diagnoses):
        overall, headline = OverallStatus.DISRUPTED, "The Internet connection appears to be unavailable."
    elif len(signal) < 3:
        overall, headline = OverallStatus.INCONCLUSIVE, "Not enough measurements to judge the connection."
    elif actionable or stats["failed"]:
        overall, headline = OverallStatus.DEGRADED, "The connection works only partly or with problems."
    else:
        overall, headline = OverallStatus.HEALTHY, "No connectivity problem was detected."
    return DiagnosticSummary(overall, headline, findings, diagnoses, blocked, stats)
