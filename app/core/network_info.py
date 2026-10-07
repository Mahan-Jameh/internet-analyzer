"""
network_info.py
================
Gathers a snapshot of the current machine's network environment for the
home screen: public IP / ISP / geo location, local adapter, gateway,
configured DNS servers and IPv4 / IPv6 availability.

All lookups are best-effort and defensive: if a piece of information
cannot be obtained (offline, restricted API, no ipconfig, etc.) the
corresponding field is simply left as ``None`` instead of raising.
"""

from __future__ import annotations

import json
import re
import socket
from typing import Optional

import requests

from app.constants import (
    HTTP_TIMEOUT,
    IP_INFO_URL,
    IP_INFO_URL_FALLBACK,
    IPV4_TEST_URL,
    IPV6_TEST_URL,
)
from app.logger import get_logger
from app.models import NetworkInfo
from app.utils.helpers import IS_WINDOWS, run_subprocess

log = get_logger(__name__)


class NetworkInfoCollector:
    """Collects a :class:`NetworkInfo` snapshot."""

    def collect(self) -> NetworkInfo:
        info = NetworkInfo()

        info.ipv4_available = self._check_ip_version(socket.AF_INET, IPV4_TEST_URL)
        info.ipv6_available = self._check_ip_version(socket.AF_INET6, IPV6_TEST_URL)
        info.internet_reachable = info.ipv4_available or info.ipv6_available

        geo = self._fetch_geo_info()
        if geo:
            info.public_ip = geo.get("ip")
            info.isp = geo.get("isp")
            info.country = geo.get("country")
            info.city = geo.get("city")

        info.dns_servers = self._get_dns_servers()
        info.adapter_name, info.gateway = self._get_adapter_and_gateway()

        return info

    # ------------------------------------------------------------------ #
    def _check_ip_version(self, family: int, url: str) -> bool:
        try:
            # Force the connection to use a specific address family by
            # resolving first, then connecting a plain socket as a fast probe.
            host = url.split("//", 1)[1].split("/", 1)[0]
            infos = socket.getaddrinfo(host, 443, family=family, type=socket.SOCK_STREAM)
            if not infos:
                return False
            addr = infos[0][4]
            with socket.socket(family, socket.SOCK_STREAM) as sock:
                sock.settimeout(3.0)
                sock.connect(addr[:2] if family == socket.AF_INET else addr)
            return True
        except OSError as exc:
            log.debug("IP version check failed for family=%s: %s", family, exc)
            return False

    def _fetch_geo_info(self) -> Optional[dict]:
        for url in (IP_INFO_URL, IP_INFO_URL_FALLBACK):
            try:
                resp = requests.get(url, timeout=HTTP_TIMEOUT)
                if resp.status_code != 200:
                    continue
                data = resp.json()
                # Normalize the two different provider schemas into one shape.
                if "ip" in data:  # ipapi.co style
                    return {
                        "ip": data.get("ip"),
                        "isp": data.get("org") or data.get("asn"),
                        "country": data.get("country_name"),
                        "city": data.get("city"),
                    }
                if "query" in data:  # ip-api.com style
                    return {
                        "ip": data.get("query"),
                        "isp": data.get("isp"),
                        "country": data.get("country"),
                        "city": data.get("city"),
                    }
            except (requests.RequestException, json.JSONDecodeError) as exc:
                log.debug("Geo IP lookup failed for %s: %s", url, exc)
                continue
        return None

    def _get_dns_servers(self) -> list[str]:
        if IS_WINDOWS:
            return self._get_dns_servers_windows()
        return self._get_dns_servers_unix()

    def _get_dns_servers_windows(self) -> list[str]:
        code, out, _ = run_subprocess(["ipconfig", "/all"], timeout=5.0)
        if code != 0:
            return []
        servers: list[str] = []
        capture = False
        for line in out.splitlines():
            if "DNS Servers" in line:
                capture = True
                match = re.search(r":\s*([\d\.a-fA-F:]+)", line)
                if match:
                    servers.append(match.group(1).strip())
                continue
            if capture:
                stripped = line.strip()
                # Continuation lines are indented and contain only an address.
                if re.match(r"^[\d\.a-fA-F:]+$", stripped):
                    servers.append(stripped)
                else:
                    capture = False
        # De-duplicate while preserving order.
        seen: set[str] = set()
        unique = [s for s in servers if not (s in seen or seen.add(s))]
        return unique

    def _get_dns_servers_unix(self) -> list[str]:
        try:
            with open("/etc/resolv.conf", "r", encoding="utf-8") as fh:
                return [
                    line.split()[1]
                    for line in fh
                    if line.strip().startswith("nameserver")
                ]
        except OSError:
            return []

    def _get_adapter_and_gateway(self) -> tuple[Optional[str], Optional[str]]:
        if IS_WINDOWS:
            return self._get_adapter_and_gateway_windows()
        return None, None

    def _get_adapter_and_gateway_windows(self) -> tuple[Optional[str], Optional[str]]:
        code, out, _ = run_subprocess(["ipconfig", "/all"], timeout=5.0)
        if code != 0:
            return None, None

        adapter_name: Optional[str] = None
        gateway: Optional[str] = None
        current_adapter: Optional[str] = None

        for line in out.splitlines():
            adapter_match = re.match(r"^(Ethernet adapter|Wireless LAN adapter) (.+):\s*$", line)
            if adapter_match:
                current_adapter = adapter_match.group(2).strip()
                continue

            if "Default Gateway" in line:
                match = re.search(r":\s*([\d\.a-fA-F:]+)", line)
                if match and match.group(1).strip():
                    gateway = match.group(1).strip()
                    adapter_name = current_adapter
                    break

        return adapter_name, gateway
