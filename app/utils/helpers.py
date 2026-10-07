"""
helpers.py
==========
Small, dependency-light utility functions shared by several core test
modules. Kept separate so that individual test modules stay focused on
one protocol / concern each.
"""

from __future__ import annotations

import ipaddress
import platform
import re
import socket
import subprocess
import time
from typing import Any

from app.logger import get_logger

log = get_logger(__name__)

IS_WINDOWS = platform.system().lower() == "windows"

# Prevents a console window from flashing open when we shell out to
# ping.exe / tracert.exe from a windowed (non-console) PyInstaller build.
_CREATE_NO_WINDOW = 0x08000000 if IS_WINDOWS else 0


def run_subprocess(args: list[str], timeout: float) -> tuple[int, str, str]:
    """
    Run an external command safely and return (return_code, stdout, stderr).
    Never raises - all failure modes are converted into a non-zero return
    code with an explanatory stderr message instead.
    """
    try:
        completed = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            creationflags=_CREATE_NO_WINDOW,
            encoding="utf-8",
            errors="replace",
        )
        return completed.returncode, completed.stdout or "", completed.stderr or ""
    except subprocess.TimeoutExpired:
        return -1, "", "Command timed out"
    except FileNotFoundError:
        return -2, "", f"Command not found: {args[0]}"
    except Exception as exc:  # pragma: no cover - defensive catch-all
        log.warning("Subprocess %s failed: %s", args, exc)
        return -3, "", str(exc)


def measure_time_ms(func, *args: Any, **kwargs: Any) -> tuple[Any, float]:
    """Run ``func`` and return (result, elapsed_milliseconds)."""
    start = time.perf_counter()
    result = func(*args, **kwargs)
    elapsed = (time.perf_counter() - start) * 1000.0
    return result, elapsed


def resolve_host(hostname: str, family: int = socket.AF_UNSPEC, timeout: float = 3.0) -> list[str]:
    """Resolve a hostname to a list of IP address strings. Returns [] on failure."""
    original_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        infos = socket.getaddrinfo(hostname, None, family=family)
        addresses = sorted({info[4][0] for info in infos})
        return addresses
    except (socket.gaierror, socket.timeout, OSError) as exc:
        log.debug("resolve_host(%s) failed: %s", hostname, exc)
        return []
    finally:
        socket.setdefaulttimeout(original_timeout)


_TTL_MARKER = re.compile(r"ttl\s*=", re.IGNORECASE)
_MS_VALUE = re.compile(r"([<=])\s*(\d+(?:[.,]\d+)?)\s*ms", re.IGNORECASE)


def parse_ping_rtts(output: str) -> list[float]:
    """
    Extract per-reply round-trip times (ms) from ``ping`` output in a way
    that does not depend on the OS language.

    Only lines that contain a ``TTL=`` marker are counted: a genuine echo
    reply always has one, while the summary line ("Minimum = 12ms, ...")
    and error lines ("Destination host unreachable") do not. Windows
    localizes the word "time" in its output but keeps "TTL" and "ms".
    A value such as ``time<1ms`` is recorded as 0.5 ms.
    """
    rtts: list[float] = []
    for line in output.splitlines():
        if not _TTL_MARKER.search(line):
            continue
        match = _MS_VALUE.search(line)
        if not match:
            continue
        value = float(match.group(2).replace(",", "."))
        if match.group(1) == "<":
            value = value / 2.0
        rtts.append(value)
    return rtts


_HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$")


def validate_target_host(text: str | None) -> str | None:
    """
    Return a cleaned hostname / IP address, or None if ``text`` is not one.
    User input is later passed to ping/tracert, so anything that could be read
    as a command-line option (a leading '-') or contains spaces is rejected.
    """
    if not text:
        return None
    candidate = text.strip()
    if not candidate or candidate.startswith("-") or any(c.isspace() for c in candidate):
        return None
    try:
        ipaddress.ip_address(candidate)
        return candidate
    except ValueError:
        pass
    return candidate if _HOSTNAME_RE.match(candidate) else None


def format_bytes(num_bytes: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if abs(num_bytes) < 1024.0:
            return f"{num_bytes:.1f} {unit}"
        num_bytes /= 1024.0
    return f"{num_bytes:.1f} TB"


def safe_str(value: Any, default: str = "N/A") -> str:
    if value is None or value == "":
        return default
    return str(value)
