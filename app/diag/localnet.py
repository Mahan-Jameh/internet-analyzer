"""
localnet.py
===========
Local network facts - interface address, default route, gateway, DNS servers -
obtained in a way that does not depend on the Windows display language.

* ``route print`` prints only numbers for the default route, so it is parsed
  by pattern instead of by (translated) field labels.
* A *connected UDP socket* asks the OS routing table which source address it
  would use for a destination, without sending a single packet. A failure
  there (WSAENETUNREACH / ENETUNREACH) means "no route for this family".
"""

from __future__ import annotations

import ipaddress
import json
import re
import socket
from dataclasses import dataclass, field

from app.diag.neterrors import NormalizedError, normalize_exception
from app.logger import get_logger
from app.utils.helpers import IS_WINDOWS, run_subprocess

log = get_logger(__name__)

_V4_DEFAULT = re.compile(r"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\S+)\s+(\d{1,3}(?:\.\d{1,3}){3})\s+(\d+)\s*$", re.MULTILINE)
_V6_DEFAULT = re.compile(r"^\s*(\d+)\s+(\d+)\s+::/0\s+(\S+)\s*$", re.MULTILINE)
_UNIX_DEFAULT = re.compile(r"^default\s+via\s+(\S+)\s+dev\s+(\S+)(?:.*?metric\s+(\d+))?", re.MULTILINE)


@dataclass
class RouteEntry:
    family: str                       # "IPv4" / "IPv6"
    gateway: str | None               # None for on-link default routes (typical for VPN/TUN adapters)
    interface: str | None = None      # interface address (IPv4) or interface index (IPv6) / device name (unix)
    metric: int | None = None

    def to_dict(self) -> dict[str, object]:
        return {"family": self.family, "gateway": self.gateway, "interface": self.interface, "metric": self.metric}


def _valid_ip(text: str) -> str | None:
    try:
        return str(ipaddress.ip_address(text.split("%")[0]))
    except ValueError:
        return None


def parse_route_print_v4(text: str) -> list[RouteEntry]:
    return [RouteEntry("IPv4", _valid_ip(m.group(1)), m.group(2), int(m.group(3)))
            for m in _V4_DEFAULT.finditer(text)]


def parse_route_print_v6(text: str) -> list[RouteEntry]:
    return [RouteEntry("IPv6", _valid_ip(m.group(3)), m.group(1), int(m.group(2)))
            for m in _V6_DEFAULT.finditer(text)]


def parse_ip_route(text: str, family: str) -> list[RouteEntry]:
    return [RouteEntry(family, _valid_ip(m.group(1)), m.group(2), int(m.group(3)) if m.group(3) else None)
            for m in _UNIX_DEFAULT.finditer(text)]


def default_routes(family: str) -> list[RouteEntry]:
    """All default routes for a family, best (lowest metric) first. Never raises."""
    try:
        if IS_WINDOWS:
            code, out, _ = run_subprocess(["route", "print", "-4" if family == "IPv4" else "-6"], timeout=6.0)
            entries = (parse_route_print_v4 if family == "IPv4" else parse_route_print_v6)(out) if code == 0 else []
        else:
            code, out, _ = run_subprocess(["ip", "-4" if family == "IPv4" else "-6", "route", "show", "default"],
                                          timeout=4.0)
            entries = parse_ip_route(out, family) if code == 0 else []
    except Exception:  # noqa: BLE001 - local facts are best-effort
        log.exception("default route lookup failed")
        return []
    return sorted(entries, key=lambda e: e.metric if e.metric is not None else 10**9)


@dataclass
class SourceAddress:
    family: str
    address: str | None
    error: NormalizedError | None = None

    @property
    def usable(self) -> bool:
        """A global or private (not loopback/link-local) source address that can reach out."""
        if not self.address:
            return False
        ip = ipaddress.ip_address(self.address)
        return not (ip.is_loopback or ip.is_link_local or ip.is_unspecified)


_ROUTE_PROBE = {"IPv4": ("8.8.8.8", socket.AF_INET), "IPv6": ("2001:4860:4860::8888", socket.AF_INET6)}


def source_address(family: str) -> SourceAddress:
    """Ask the routing table which local address would be used (sends no packet)."""
    dest, af = _ROUTE_PROBE[family]
    try:
        with socket.socket(af, socket.SOCK_DGRAM) as sock:
            sock.connect((dest, 9))
            return SourceAddress(family, sock.getsockname()[0])
    except OSError as exc:
        return SourceAddress(family, None, normalize_exception(exc))


def local_addresses(family: str) -> list[str]:
    """Addresses assigned to this host (best effort, stdlib only)."""
    af = socket.AF_INET if family == "IPv4" else socket.AF_INET6
    found: list[str] = []
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, af):
            addr = str(info[4][0]).split("%")[0]
            if addr not in found:
                found.append(addr)
    except OSError:
        pass
    return found


# ---- DNS configuration -----------------------------------------------------
def parse_ipconfig_dns(text: str) -> list[str]:
    """English-label parser (kept as fallback); see :func:`dns_servers`."""
    servers: list[str] = []
    capture = False
    for line in text.splitlines():
        if "DNS Servers" in line:
            capture = True
            match = re.search(r":\s*([\d\.a-fA-F:%]+)", line)
            if match:
                servers.append(match.group(1).strip())
            continue
        if capture:
            stripped = line.strip()
            if re.match(r"^[\d\.a-fA-F:%]+$", stripped):
                servers.append(stripped)
            else:
                capture = False
    return servers


def parse_powershell_dns(text: str) -> list[str]:
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return []
    if isinstance(data, dict):
        data = [data]
    servers: list[str] = []
    for item in data or []:
        addrs = item.get("ServerAddresses") if isinstance(item, dict) else None
        for a in addrs or []:
            if _valid_ip(str(a)):
                servers.append(str(a))
    return servers


def dns_servers() -> list[str]:
    """Configured DNS servers, de-duplicated, order preserved. Never raises."""
    servers: list[str] = []
    try:
        if IS_WINDOWS:
            code, out, _ = run_subprocess(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command",
                 "Get-DnsClientServerAddress | Where-Object {$_.ServerAddresses} | "
                 "Select-Object -Property ServerAddresses | ConvertTo-Json -Compress"], timeout=8.0)
            if code == 0:
                servers = parse_powershell_dns(out)
            if not servers:
                code, out, _ = run_subprocess(["ipconfig", "/all"], timeout=6.0)
                servers = parse_ipconfig_dns(out) if code == 0 else []
        else:
            with open("/etc/resolv.conf", "r", encoding="utf-8") as fh:
                servers = [ln.split()[1] for ln in fh if ln.strip().startswith("nameserver") and len(ln.split()) > 1]
    except OSError:
        servers = []
    seen: set[str] = set()
    return [s for s in servers if not (s in seen or seen.add(s))]


def adapter_name_for_ip(ipconfig_text: str, ip: str) -> str | None:
    """Find the adapter block of ``ipconfig /all`` that contains ``ip`` (language independent)."""
    header: str | None = None
    for line in ipconfig_text.splitlines():
        if line and not line[0].isspace() and line.rstrip().endswith(":"):
            header = line.rstrip().rstrip(":")
        elif header and re.search(rf"(?<![\d.]){re.escape(ip)}(?![\d.])", line):
            return re.sub(r"^(Ethernet adapter|Wireless LAN adapter|Unknown adapter)\s+", "", header).strip()
    return None


@dataclass
class LocalNetwork:
    ipv4: SourceAddress
    ipv6: SourceAddress
    routes_v4: list[RouteEntry] = field(default_factory=list)
    routes_v6: list[RouteEntry] = field(default_factory=list)
    adapter_name: str | None = None
    dns: list[str] = field(default_factory=list)

    @property
    def gateway(self) -> str | None:
        for r in self.routes_v4:
            if r.gateway:
                return r.gateway
        return None


def collect_local_network() -> LocalNetwork:
    v4, v6 = source_address("IPv4"), source_address("IPv6")
    routes4, routes6 = default_routes("IPv4"), default_routes("IPv6")
    adapter = None
    if IS_WINDOWS and v4.address:
        code, out, _ = run_subprocess(["ipconfig", "/all"], timeout=6.0)
        adapter = adapter_name_for_ip(out, v4.address) if code == 0 else None
    return LocalNetwork(v4, v6, routes4, routes6, adapter, dns_servers())
