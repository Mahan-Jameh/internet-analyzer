"""
environment_check.py
====================
Looks for a proxy or VPN/tunnel on THIS computer. When one is active, every
other test measures the tunnel and its exit point instead of the user's
real connection, which changes how all results must be read.

Every signal is reported on its own and only as EVIDENCE (INFO severity, never
an error): detecting a proxy or VPN is not a failure, it is context.

    system proxy (WinINET registry) | WinHTTP proxy | environment proxy variables
    local proxy listeners | VPN/tunnel adapters (and whether they look connected)
    virtual adapters (Hyper-V/VMware/VirtualBox - not VPNs) | DNS servers set on a tunnel adapter

Everything only ever *observes* the local machine; nothing is changed.
"""

from __future__ import annotations

import os
import re
import socket
import threading
from typing import Any, Callable, Optional

from app.constants import (
    LOCAL_PORT_TIMEOUT,
    LOCAL_PROXY_PORTS,
    PROXY_ENV_VARS,
    VPN_ADAPTER_HINTS,
)
from app.diag.adapter import check_from_result
from app.diag.results import Severity, TechnicalStatus, TestResult
from app.logger import get_logger
from app.models import CheckResult, ModuleReport
from app.utils.helpers import IS_WINDOWS, run_subprocess

log = get_logger(__name__)
_S = TechnicalStatus

ProgressCallback = Optional[Callable[[str], None]]

VIRTUAL_HINTS = ("hyper-v", "vmware", "virtualbox", "vethernet", "host-only", "loopback", "wsl", "docker")
_IPV4_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")


def find_vpn_adapter_lines(text: str) -> list[str]:
    """
    Return the adapter/description lines of ``ipconfig /all`` (or ``ip link``)
    output whose text contains a VPN-like keyword. Pure function for testing.
    """
    found: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        lowered = stripped.lower()
        is_header = lowered.endswith(":") and "adapter" in lowered
        is_description = lowered.startswith("description")
        is_linux_link = ": " in stripped and stripped[:1].isdigit()
        if not (is_header or is_description or is_linux_link):
            continue
        if any(hint in lowered for hint in VPN_ADAPTER_HINTS):
            found.append(stripped)
    return found


def parse_adapter_sections(text: str) -> list[dict[str, Any]]:
    """
    Split ``ipconfig /all`` into adapters. Language-independent where it matters:
    the header ends with ':' at column 0, a disconnected adapter has no IPv4 address,
    and DNS servers are the IPv4 literals following the DNS line.
    """
    sections: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    in_dns = False
    for raw in text.splitlines():
        if raw and not raw[0].isspace() and raw.rstrip().endswith(":"):
            current = {"header": raw.strip(), "description": "", "ipv4": [], "dns": [], "text": []}
            sections.append(current)
            in_dns = False
            continue
        if current is None:
            continue
        line = raw.strip()
        if not line:
            continue
        current["text"].append(line)
        key = line.split(":", 1)[0].lower()
        if line.lower().startswith("description"):
            current["description"] = line.split(":", 1)[-1].strip()
            in_dns = False
        elif "dns" in key and ":" in line:
            in_dns = True
            current["dns"] += _IPV4_RE.findall(line.split(":", 1)[1])
        elif in_dns and ":" not in line:
            current["dns"] += _IPV4_RE.findall(line)
        else:
            in_dns = False
            if ("ipv4" in key or "ip address" in key) and ":" in line:
                current["ipv4"] += [a for a in _IPV4_RE.findall(line.split(":", 1)[1])
                                    if not a.startswith("169.254.")]
    return sections


def classify_adapter(section: dict[str, Any]) -> str:
    label = f"{section['header']} {section['description']}".lower()
    if any(h in label for h in VIRTUAL_HINTS):
        return "virtual"
    if any(h in label for h in VPN_ADAPTER_HINTS):
        return "vpn"
    return "physical"


def parse_winhttp_proxy(text: str) -> Optional[str]:
    """``netsh winhttp show proxy`` -> the proxy server string, or None for direct access."""
    for line in text.splitlines():
        if ":" in line and re.search(r"\d|\w\.\w", line.split(":", 1)[1]):
            value = line.split(":", 1)[1].strip()
            if "=" in value or re.search(r":\d{2,5}\b", value):
                return value
    return None


def _evidence(test_id: str, category: str, detected: bool, summary: str, **meta: Any) -> TestResult:
    res = TestResult(test_id, category, status=_S.SUCCESS, severity=Severity.INFO, protocol=None,
                     summary=summary, metadata={"detected": detected, "role": "evidence", **meta})
    return res


class EnvironmentChecker:
    def __init__(self, progress_cb: ProgressCallback = None, cancel: Optional[threading.Event] = None) -> None:
        self.progress_cb = progress_cb
        self.cancel = cancel or threading.Event()

    def _report(self, message: str) -> None:
        if self.progress_cb:
            self.progress_cb(message)
        log.info(message)

    def run_all(self) -> ModuleReport:
        report = ModuleReport(module_name="Proxy & VPN Detection")
        self._report("Checking for an active proxy or VPN on this computer ...")
        for step in (self._system_proxy, self._winhttp_proxy, self._env_proxy,
                     self._local_proxy_ports, self._vpn_adapters):
            if self.cancel.is_set():
                break
            try:
                out = step()
            except Exception as exc:  # noqa: BLE001 - detection is best-effort, never crash
                log.exception("Environment step %s crashed", step.__name__)
                res = TestResult(f"env.{step.__name__.strip('_')}", "environment", status=_S.ERROR,
                                 severity=Severity.INFO, error_type=type(exc).__name__,
                                 summary="This check could not be completed.")
                out = [check_from_result(step.__name__.strip("_"), res)]
            for check in out if isinstance(out, list) else [out]:
                report.add(check)
                if isinstance(check.result, TestResult):
                    report.results.append(check.result)
        report.finish()
        return report

    # ------------------------------------------------------------------ #
    def _finish(self, name: str, res: TestResult, findings: list[str], key: str,
                none_message: str, found_message: str, extra: dict[str, Any] | None = None) -> CheckResult:
        detected = bool(findings)
        res.metadata["detected"] = detected
        res.metadata["detail"] = findings
        res.summary = found_message if detected else none_message
        for f in findings:
            res.add_evidence(f)
        details = {key: findings, "suspected": detected, "detected": detected, **(extra or {})}
        return check_from_result(name, res, details=details)

    def _system_proxy(self) -> CheckResult:
        findings: list[str] = []
        if IS_WINDOWS:
            try:
                import winreg  # only exists on Windows

                key_path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path) as key:
                    def _value(value_name: str):
                        try:
                            return winreg.QueryValueEx(key, value_name)[0]
                        except OSError:
                            return None

                    if _value("ProxyEnable") == 1 and _value("ProxyServer"):
                        findings.append(f"system proxy enabled: {_value('ProxyServer')}")
                    if _value("AutoConfigURL"):
                        findings.append(f"proxy auto-config script: {_value('AutoConfigURL')}")
            except (ImportError, OSError) as exc:
                log.debug("Could not read proxy settings: %s", exc)
        res = _evidence("env.system_proxy", "proxy", False, "", source="wininet")
        return self._finish(
            "System Proxy Settings", res, findings, "findings",
            "No system proxy is configured.",
            "A system proxy is configured (" + "; ".join(findings) + "). Browser-style traffic may go "
            "through it; this is context, not a fault.")

    def _winhttp_proxy(self) -> CheckResult:
        findings: list[str] = []
        res = _evidence("env.winhttp_proxy", "proxy", False, "", source="winhttp")
        if IS_WINDOWS:
            code, out, _ = run_subprocess(["netsh", "winhttp", "show", "proxy"], timeout=6)
            if code == 0:
                server = parse_winhttp_proxy(out)
                if server:
                    findings.append(f"WinHTTP proxy: {server}")
            else:
                res.status = _S.INCONCLUSIVE
        else:
            res.status = _S.NOT_APPLICABLE
            res.severity = Severity.INFO
        return self._finish("WinHTTP Proxy", res, findings, "findings",
                            "WinHTTP uses a direct connection (no proxy)." if res.status is _S.SUCCESS
                            else "The WinHTTP proxy setting could not be read.",
                            "A WinHTTP proxy is configured (" + "; ".join(findings) + ").")

    def _env_proxy(self) -> CheckResult:
        names = [v for v in PROXY_ENV_VARS if os.environ.get(v)]
        findings = [f"environment variable {v} is set" for v in names[:1]]
        res = _evidence("env.env_proxy", "proxy", False, "", source="environment")
        return self._finish("Environment Proxy Variables", res, findings, "findings",
                            "No proxy environment variables are set.",
                            "A proxy environment variable is set; programs that honour it will use the proxy.")

    def _local_proxy_ports(self) -> CheckResult:
        listening: dict[int, str] = {}
        for port, description in LOCAL_PROXY_PORTS.items():
            if self.cancel.is_set():
                break
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(LOCAL_PORT_TIMEOUT)
                    if sock.connect_ex(("127.0.0.1", port)) == 0:
                        listening[port] = description
            except OSError:
                continue
        findings = [f"{p} ({d})" for p, d in sorted(listening.items())]
        res = _evidence("env.local_proxy_ports", "proxy", False, "", source="localhost_ports")
        res.confidence = 0.4 if findings else None   # another program can use the same port
        return self._finish(
            "Local Proxy Listeners", res, findings, "ports",
            "Nothing is listening on the common local proxy ports checked.",
            "Something is listening on common proxy ports of this computer: " + ", ".join(findings) +
            ". A proxy or VPN program may be running, but another program can use the same port, "
            "so this is only a hint.",
            extra={"ports": {str(p): d for p, d in listening.items()}})

    def _vpn_adapters(self) -> list[CheckResult]:
        if IS_WINDOWS:
            code, out, _ = run_subprocess(["ipconfig", "/all"], timeout=8)
        else:
            code, out, _ = run_subprocess(["ip", "-o", "link", "show"], timeout=5)
        if code != 0 or not out.strip():
            res = _evidence("env.vpn_adapters", "vpn", False, "The list of network adapters could not be read.")
            res.status = _S.INCONCLUSIVE
            return [check_from_result("VPN / Tunnel Adapters", res)]
        return self.evaluate_adapters(out)

    def evaluate_adapters(self, text: str) -> list[CheckResult]:
        """Pure-ish: turns adapter-listing text into evidence results (testable without a shell)."""
        sections = parse_adapter_sections(text) if IS_WINDOWS or "adapter" in text.lower() else []
        vpn_lines = find_vpn_adapter_lines(text)
        vpn_secs = [s for s in sections if classify_adapter(s) == "vpn"]
        virt_secs = [s for s in sections if classify_adapter(s) == "virtual"]
        connected = [s for s in vpn_secs if s["ipv4"]]

        res = _evidence("env.vpn_adapters", "vpn", False, "", source="adapters", kind="vpn_adapter")
        res.metrics.update(adapters=[s["header"] for s in vpn_secs] or vpn_lines,
                           connected=[s["header"] for s in connected])
        if connected:
            res.confidence = 0.7
        msg_found = ("Adapters with VPN/tunnel-like names exist: " + " | ".join((vpn_lines or [s["header"] for s in vpn_secs])[:4])
                     + (". At least one has an IPv4 address, so a tunnel may be active; results then describe "
                        "the tunnel rather than your direct connection." if connected else
                        ". None of them has an address, so they look installed but not connected."))
        vpn_check = self._finish("VPN / Tunnel Adapters", res, vpn_lines or [s["header"] for s in vpn_secs],
                                 "adapters", "No adapters with VPN/tunnel-like names were found.", msg_found,
                                 extra={"adapters": vpn_lines, "connected": bool(connected), "suspected": bool(connected)})
        out = [vpn_check]

        vres = _evidence("env.virtual_adapters", "vpn", False, "", source="adapters", kind="virtual_adapter")
        out.append(self._finish("Virtual Adapters", vres, [s["header"] for s in virt_secs], "adapters",
                                "No virtual-machine/container adapters were found.",
                                "Virtual adapters (VM or container networking) exist. They are not VPNs, but "
                                "can add routes and DNS entries.",
                                extra={"suspected": False}))
        tunnel_dns = sorted({d for s in connected for d in s["dns"]})
        dres = _evidence("env.vpn_dns", "vpn", False, "", source="adapters", kind="vpn_dns")
        out.append(self._finish("DNS Through Tunnel Adapter", dres,
                                [f"DNS server {d} is set on a tunnel adapter" for d in tunnel_dns], "dns_servers",
                                "No DNS server is set on a connected tunnel adapter.",
                                "A connected tunnel adapter supplies DNS servers, so name lookups may go through "
                                "the tunnel.", extra={"suspected": False}))
        return out
