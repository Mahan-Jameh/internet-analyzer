"""
network_info.py
================
Snapshot of the machine's network environment for the home screen, built from
*separate layers* instead of one boolean:

    IPv4 / IPv6:  1. address configured on the local interface
                  2. default route available
                  3. DNS can resolve an address of that family
                  4. a TCP connection to an external address of that family works

"IPv4: False / IPv6: False" is never reported on the strength of one failed
``getaddrinfo`` call. The public IP is an *auxiliary* lookup: failing to find
it does not make the connection "down".

Every lookup is best-effort and defensive; a missing piece is left as ``None``.
"""

from __future__ import annotations

import ipaddress
import json
import threading
from typing import Any, Optional

import requests

from app.constants import IP_INFO_URL, IP_INFO_URL_FALLBACK
from app.diag.localnet import LocalNetwork, collect_local_network
from app.diag.probes import resolve, tcp_probe
from app.diag.results import Severity, TechnicalStatus, TestResult
from app.diag.testconfig import DEFAULT_CONFIG, NetworkTestConfig
from app.logger import get_logger
from app.models import NetworkInfo

log = get_logger(__name__)
_S = TechnicalStatus

IP_STATE_AVAILABLE = "Available"
IP_STATE_NOT_CONFIGURED = "Not configured"
IP_STATE_NO_INTERNET = "Configured, but no Internet access"
IP_STATE_UNKNOWN = "Unknown"

PUBLIC_IP_DETECTED = "PUBLIC_IP_DETECTED"
PUBLIC_IP_LOOKUP_FAILED = "LOOKUP_FAILED"
PUBLIC_IP_NOT_AVAILABLE = "NOT_AVAILABLE"
PUBLIC_IP_NOT_TESTED = "NOT_TESTED"

_DNS_PROBE_NAME = "www.cloudflare.com"


class NetworkInfoCollector:
    """Collects a :class:`NetworkInfo` snapshot plus the detailed :class:`TestResult` objects."""

    def __init__(self, config: NetworkTestConfig = DEFAULT_CONFIG, cancel: threading.Event | None = None) -> None:
        self.config = config
        self.cancel = cancel or threading.Event()

    # ------------------------------------------------------------------ #
    def collect(self, include_public_ip: bool = True) -> NetworkInfo:
        info = NetworkInfo()
        local = collect_local_network()
        results: list[TestResult] = []

        v4 = self.check_ip_family("IPv4", local)
        v6 = self.check_ip_family("IPv6", local)
        results += [v4, v6]
        info.ip_layers = {"ipv4": v4.metrics, "ipv6": v6.metrics}
        info.ipv4_state, info.ipv6_state = _state_text(v4), _state_text(v6)
        info.ipv4_available = v4.ok
        info.ipv6_available = v6.ok
        # Internet connectivity is proven by TCP to external IP literals, not by the public-IP service.
        info.internet_reachable = v4.ok or v6.ok

        info.dns_servers = local.dns
        info.adapter_name, info.gateway = local.adapter_name, local.gateway

        if include_public_ip and not self.cancel.is_set():
            ip_result, geo = self.lookup_public_ip()
            results.append(ip_result)
            info.public_ip_state = ip_result.metadata["state"]
            if geo:
                info.public_ip = geo.get("ip")
                info.isp, info.country, info.city = geo.get("isp"), geo.get("country"), geo.get("city")
        info.test_results = results
        return info

    # ------------------------------------------------------------------ #
    def check_ip_family(self, family: str, local: Optional[LocalNetwork] = None) -> TestResult:
        """Layered IPv4/IPv6 availability as one :class:`TestResult` (layers in ``metrics``)."""
        local = local or collect_local_network()
        src = local.ipv4 if family == "IPv4" else local.ipv6
        routes = local.routes_v4 if family == "IPv4" else local.routes_v6
        hosts = (self.config.targets.ipv4_probe_hosts if family == "IPv4"
                 else self.config.targets.ipv6_probe_hosts)

        configured = src.usable
        # IPv6 link-local only does not count as configured for Internet use.
        default_route = bool(routes) or (src.address is not None)
        metrics: dict[str, Any] = {
            "configured": configured, "default_route": default_route, "local_address": src.address,
            "default_gateways": [r.to_dict() for r in routes],
            "dns_resolves": None, "internet_connectivity": False, "probes": [],
        }
        result = TestResult(f"{family.lower()}", "ip_family", address_family=family, protocol="TCP",
                            port=443, metrics=metrics, severity=None)
        result.add_evidence(f"Local {family} address: {src.address or 'none usable'}")
        result.add_evidence(f"Default route: {'present' if default_route else 'absent'}")

        if configured and default_route:
            ok_hosts = []
            for host in hosts:
                if self.cancel.is_set():
                    break
                probe = tcp_probe(host, 443, self.config, family=family, role="family_check",
                                  test_id=f"tcp.{host}.443", retry=False)
                metrics["probes"].append({"host": host, "status": probe.status.value,
                                          "duration_ms": probe.duration_ms, "error_code": probe.error_code})
                if probe.ok:
                    ok_hosts.append(host)
                    break                                   # one success proves the layer
            metrics["internet_connectivity"] = bool(ok_hosts)
            # DNS capability for this family is checked only when it matters (informational).
            res = resolve(_DNS_PROBE_NAME, family)
            metrics["dns_resolves"] = res.ok
            if ok_hosts:
                result.status = _S.SUCCESS
                result.add_evidence(f"TCP/443 to {ok_hosts[0]} succeeded over {family}")
                result.summary = f"{family}: available."
            else:
                last = metrics["probes"][-1] if metrics["probes"] else {}
                result.status = _S.UNREACHABLE if last.get("status") == "UNREACHABLE" else _S.TIMEOUT
                result.error_code = last.get("error_code")
                result.summary = f"{family} is configured but external {family} connections failed."
                result.add_evidence(f"External {family} probes failed ({last.get('status', 'no probe')})")
        else:
            result.status = _S.UNREACHABLE
            result.interpretation = "NOT_CONFIGURED"
            result.confidence = 0.9
            result.error_code = src.error.error_code if src.error else "NO_ADDRESS"
            result.summary = f"{family} is not configured on this connection."
            result.add_evidence(f"No usable {family} source address / route "
                                f"({src.error.error_code if src.error else 'none found'})")

        # Severity: IPv6 absent is normal; IPv4 problems matter; broken-but-configured IPv6 is a warning.
        if result.status is _S.SUCCESS:
            result.severity = Severity.OK
        elif not configured:
            result.severity = Severity.INFO if family == "IPv6" else Severity.ERROR
        else:
            result.severity = Severity.WARNING if family == "IPv6" else Severity.ERROR
        return result

    # ------------------------------------------------------------------ #
    def lookup_public_ip(self) -> tuple[TestResult, Optional[dict[str, Any]]]:
        """
        Auxiliary public-IP / geo lookup. Never an error: the worst outcome is
        ``LOOKUP_FAILED`` at INFO severity. Several endpoints are compared.
        """
        answers: list[dict[str, Any]] = []
        failures: list[str] = []
        for url in (IP_INFO_URL, IP_INFO_URL_FALLBACK):
            if self.cancel.is_set():
                break
            geo, why = self._fetch_geo(url)
            if geo:
                answers.append({"endpoint": url.split("/")[2], **geo})
            else:
                failures.append(f"{url.split('/')[2]}: {why}")

        result = TestResult("public_ip", "public_ip", protocol="HTTPS", severity=Severity.INFO,
                            metrics={"endpoints": answers, "failures": failures})
        if not answers:
            result.status = _S.INCONCLUSIVE
            result.metadata["state"] = PUBLIC_IP_LOOKUP_FAILED
            result.summary = "The public IP address could not be looked up (this does not mean the Internet is down)."
            for f in failures:
                result.add_evidence(f"Lookup failed - {f}")
            return result, None

        ips = {a["ip"] for a in answers if a.get("ip")}
        result.status = _S.SUCCESS
        result.metadata["state"] = PUBLIC_IP_DETECTED
        result.metrics["consistent"] = len(ips) == 1
        result.summary = f"Public IP detected: {answers[0].get('ip')}."
        if len(ips) > 1:
            result.warnings.append("Lookup services disagree about the public IP (possible proxy/VPN or CGNAT).")
        first = answers[0]
        return result, {"ip": first.get("ip"), "isp": first.get("isp"),
                        "country": first.get("country"), "city": first.get("city")}

    def _fetch_geo(self, url: str) -> tuple[Optional[dict[str, Any]], str]:
        try:
            resp = requests.get(url, timeout=self.config.read_timeout)
            if resp.status_code != 200:
                return None, f"HTTP {resp.status_code}"
            data = resp.json()
        except (requests.RequestException, json.JSONDecodeError, ValueError) as exc:
            log.debug("Geo IP lookup failed for %s: %s", url, exc)
            return None, type(exc).__name__
        ip = data.get("ip") or data.get("query")
        try:
            ipaddress.ip_address(str(ip))
        except ValueError:
            return None, "no valid address in reply"
        if "ip" in data:  # ipapi.co style
            return {"ip": ip, "isp": data.get("org") or data.get("asn"),
                    "country": data.get("country_name"), "city": data.get("city")}, ""
        return {"ip": ip, "isp": data.get("isp"), "country": data.get("country"), "city": data.get("city")}, ""


def _state_text(result: TestResult) -> str:
    if result.ok:
        return IP_STATE_AVAILABLE
    if result.metrics.get("configured") is False:
        return IP_STATE_NOT_CONFIGURED
    return IP_STATE_NO_INTERNET
