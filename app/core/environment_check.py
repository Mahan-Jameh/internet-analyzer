"""
environment_check.py
====================
Looks for a proxy or VPN/tunnel on THIS computer. When one is active, every
other test measures the tunnel and its exit point instead of the user's
real connection, which changes how all results must be read.

Three independent signals are checked, each reported on its own:
    1. system proxy settings (Windows registry, or environment variables)
    2. programs listening on well known local proxy ports (127.0.0.1 only)
    3. network adapters whose names look like VPN/TUN/tunnel adapters

All three only ever *observe* the local machine; nothing is changed.
"""

from __future__ import annotations

import os
import socket
from typing import Callable, Optional

from app.constants import (
    LOCAL_PORT_TIMEOUT,
    LOCAL_PROXY_PORTS,
    PROXY_ENV_VARS,
    VPN_ADAPTER_HINTS,
)
from app.logger import get_logger
from app.models import CheckResult, ModuleReport, Status
from app.utils.helpers import IS_WINDOWS, run_subprocess

log = get_logger(__name__)

ProgressCallback = Optional[Callable[[str], None]]


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


class EnvironmentChecker:
    def __init__(self, progress_cb: ProgressCallback = None) -> None:
        self.progress_cb = progress_cb

    def _report(self, message: str) -> None:
        if self.progress_cb:
            self.progress_cb(message)
        log.info(message)

    def run_all(self) -> ModuleReport:
        report = ModuleReport(module_name="Proxy & VPN Detection")
        self._report("Checking for an active proxy or VPN on this computer ...")
        report.add(self._system_proxy())
        report.add(self._local_proxy_ports())
        report.add(self._vpn_adapters())
        report.finish()
        return report

    # ------------------------------------------------------------------ #
    def _system_proxy(self) -> CheckResult:
        name = "System Proxy Settings"
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

        for var in PROXY_ENV_VARS:
            if os.environ.get(var):
                findings.append(f"environment variable {var} is set")
                break

        if findings:
            return CheckResult(
                name=name, status=Status.WARNING,
                message=("A proxy appears to be configured (" + "; ".join(findings) + "). "
                         "Test traffic may be going through it instead of your direct connection."),
                details={"findings": findings, "suspected": True})
        return CheckResult(name=name, status=Status.OK,
                           message="No system proxy is configured.",
                           details={"findings": [], "suspected": False})

    def _local_proxy_ports(self) -> CheckResult:
        name = "Local Proxy Listeners"
        listening: dict[int, str] = {}
        for port, description in LOCAL_PROXY_PORTS.items():
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(LOCAL_PORT_TIMEOUT)
                    if sock.connect_ex(("127.0.0.1", port)) == 0:
                        listening[port] = description
            except OSError:
                continue

        if listening:
            shown = ", ".join(f"{p} ({d})" for p, d in sorted(listening.items()))
            return CheckResult(
                name=name, status=Status.WARNING,
                message=("Something is listening on common proxy ports of this computer: "
                         f"{shown}. A proxy or VPN program may be running. Another program "
                         "can use the same port for something unrelated, so this is only a hint."),
                details={"ports": {str(p): d for p, d in listening.items()}, "suspected": True})
        return CheckResult(name=name, status=Status.OK,
                           message="Nothing is listening on the common local proxy ports checked.",
                           details={"ports": {}, "suspected": False})

    def _vpn_adapters(self) -> CheckResult:
        name = "VPN / Tunnel Adapters"
        if IS_WINDOWS:
            code, out, _ = run_subprocess(["ipconfig", "/all"], timeout=8)
        else:
            code, out, _ = run_subprocess(["ip", "-o", "link", "show"], timeout=5)

        if code != 0 or not out.strip():
            return CheckResult(name=name, status=Status.UNKNOWN,
                               message="The list of network adapters could not be read.")

        lines = find_vpn_adapter_lines(out)
        if lines:
            return CheckResult(
                name=name, status=Status.WARNING,
                message=("Adapters with VPN/tunnel-like names exist: " + " | ".join(lines[:4])
                         + ". Having one installed does not mean it is connected, but if it is, "
                         "results describe the tunnel rather than your direct connection."),
                details={"adapters": lines, "suspected": True})
        return CheckResult(name=name, status=Status.OK,
                           message="No adapters with VPN/tunnel-like names were found.",
                           details={"adapters": [], "suspected": False})
