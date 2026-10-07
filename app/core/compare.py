"""
compare.py
==========
Compares two saved reports (as plain dicts, i.e. ``FullReport.to_dict()``
output) and lists every check whose status changed, plus checks that
appeared or disappeared and changes in the network environment.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

# Lower is better. UNKNOWN sits between OK and WARNING: "not confirmed good".
_RANK = {"OK": 0, "UNKNOWN": 1, "WARNING": 2, "FAILED": 3}

IMPROVED = "improved"
DEGRADED = "degraded"
CHANGED = "changed"
NEW = "new"
REMOVED = "removed"

_NETWORK_FIELDS = [
    ("public_ip", "Public IP"),
    ("isp", "ISP"),
    ("country", "Country"),
    ("city", "City"),
    ("ipv4_available", "IPv4 available"),
    ("ipv6_available", "IPv6 available"),
    ("dns_servers", "DNS servers"),
    ("adapter_name", "Network adapter"),
    ("gateway", "Gateway"),
    ("internet_reachable", "Internet reachable"),
]


@dataclass(frozen=True)
class CheckDiff:
    module: str
    check: str
    old_status: str | None
    new_status: str | None
    old_message: str
    new_message: str
    change: str


@dataclass(frozen=True)
class NetworkChange:
    label: str
    old: str
    new: str


@dataclass
class ComparisonResult:
    check_diffs: list[CheckDiff]
    network_changes: list[NetworkChange]
    unchanged_count: int

    @property
    def improved(self) -> int:
        return sum(1 for d in self.check_diffs if d.change == IMPROVED)

    @property
    def degraded(self) -> int:
        return sum(1 for d in self.check_diffs if d.change == DEGRADED)


def _index_checks(report: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    indexed: dict[tuple[str, str], dict[str, Any]] = {}
    for module in report.get("modules", []):
        module_name = module.get("module_name", "?")
        for check in module.get("checks", []):
            indexed[(module_name, check.get("name", "?"))] = check
    return indexed


def _fmt(value: Any) -> str:
    if value is None or value == "" or value == []:
        return "N/A"
    if isinstance(value, bool):
        return "Yes" if value else "No"
    if isinstance(value, list):
        return ", ".join(str(v) for v in value)
    return str(value)


def compare_reports(old: dict[str, Any], new: dict[str, Any]) -> ComparisonResult:
    """Compare ``old`` (earlier run) against ``new`` (later run)."""
    old_checks = _index_checks(old)
    new_checks = _index_checks(new)

    diffs: list[CheckDiff] = []
    unchanged = 0

    for key in sorted(set(old_checks) | set(new_checks)):
        module, name = key
        before = old_checks.get(key)
        after = new_checks.get(key)

        if before is None and after is not None:
            diffs.append(CheckDiff(module, name, None, after["status"],
                                   "", after.get("message", ""), NEW))
        elif after is None and before is not None:
            diffs.append(CheckDiff(module, name, before["status"], None,
                                   before.get("message", ""), "", REMOVED))
        elif before is not None and after is not None:
            if before["status"] == after["status"]:
                unchanged += 1
                continue
            old_rank = _RANK.get(before["status"], 1)
            new_rank = _RANK.get(after["status"], 1)
            if new_rank < old_rank:
                change = IMPROVED
            elif new_rank > old_rank:
                change = DEGRADED
            else:
                change = CHANGED
            diffs.append(CheckDiff(module, name, before["status"], after["status"],
                                   before.get("message", ""), after.get("message", ""), change))

    old_net = old.get("network_info", {}) or {}
    new_net = new.get("network_info", {}) or {}
    net_changes = [
        NetworkChange(label, _fmt(old_net.get(key)), _fmt(new_net.get(key)))
        for key, label in _NETWORK_FIELDS
        if old_net.get(key) != new_net.get(key)
    ]

    return ComparisonResult(diffs, net_changes, unchanged)
