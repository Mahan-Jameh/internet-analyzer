"""
exporter.py
===========
Converts a :class:`FullReport` into TXT, JSON, CSV or a self-contained
HTML report file. Each exporter is a pure function that returns the
file content as text (or bytes), and a small `save_report` helper is
provided to write it to disk, all of which are exercised by the GUI's
export dialog.
"""

from __future__ import annotations

import csv
import html
import io
import json
from datetime import datetime
from pathlib import Path

from app.constants import STATUS_COLORS
from app.models import FullReport

_STATUS_SYMBOLS = {"OK": "✔", "WARNING": "⚠", "FAILED": "✖", "UNKNOWN": "?"}


def to_txt(report: FullReport) -> str:
    lines: list[str] = []
    lines.append("=" * 70)
    lines.append("INTERNET CONNECTIVITY & PROTOCOL ANALYZER - REPORT")
    lines.append("=" * 70)
    lines.append(f"Generated: {report.generated_at:%Y-%m-%d %H:%M:%S}")
    if report.profile_name:
        lines.append(f"Profile: {report.profile_name}")
    lines.append("")

    lines.append("-- Network Information --")
    info = report.network_info
    lines.append(f"Public IP     : {info.public_ip or 'N/A'}")
    lines.append(f"ISP           : {info.isp or 'N/A'}")
    lines.append(f"Country       : {info.country or 'N/A'}")
    lines.append(f"City          : {info.city or 'N/A'}")
    lines.append(f"IPv4 Available: {info.ipv4_available}")
    lines.append(f"IPv6 Available: {info.ipv6_available}")
    lines.append(f"DNS Servers   : {', '.join(info.dns_servers) or 'N/A'}")
    lines.append(f"Adapter       : {info.adapter_name or 'N/A'}")
    lines.append(f"Gateway       : {info.gateway or 'N/A'}")
    lines.append(f"Internet OK   : {info.internet_reachable}")
    lines.append("")

    for module in report.modules:
        lines.append("-" * 70)
        lines.append(f"MODULE: {module.module_name}  [{module.overall_status.value}]")
        lines.append("-" * 70)
        for check in module.checks:
            symbol = _STATUS_SYMBOLS.get(check.status.value, "?")
            duration = f" ({check.duration_ms:.0f} ms)" if check.duration_ms else ""
            lines.append(f"  {symbol} {check.name}{duration}")
            if check.message:
                lines.append(f"      {check.message}")
        lines.append("")

    lines.append("=" * 70)
    lines.append("ANALYSIS / POSSIBLE INTERPRETATIONS (probabilistic, not definitive)")
    lines.append("=" * 70)
    for interp in report.interpretations:
        symbol = _STATUS_SYMBOLS.get(interp.severity.value, "?")
        lines.append(f"  {symbol} {interp.text}")

    return "\n".join(lines)


def to_json(report: FullReport) -> str:
    return json.dumps(report.to_dict(), indent=2, ensure_ascii=False)


def _csv_safe(text: str) -> str:
    """Stop spreadsheet programs from running text such as '=cmd|...' as a formula."""
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text


def to_csv(report: FullReport) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["Module", "Check", "Status", "Message", "Duration (ms)", "Timestamp"])
    for module in report.modules:
        for check in module.checks:
            writer.writerow([
                _csv_safe(module.module_name),
                _csv_safe(check.name),
                check.status.value,
                _csv_safe(check.message),
                f"{check.duration_ms:.1f}" if check.duration_ms else "",
                check.timestamp.isoformat(),
            ])
    return buffer.getvalue()


def to_html(report: FullReport) -> str:
    info = report.network_info

    def esc(value: object) -> str:
        """Everything that came from the network or a log is untrusted: escape it."""
        return html.escape("" if value is None else str(value))

    def status_badge(status_value: str) -> str:
        color = STATUS_COLORS.get(status_value, "#95a5a6")
        symbol = _STATUS_SYMBOLS.get(status_value, "?")
        return (
            f'<span style="display:inline-block;padding:2px 10px;border-radius:10px;'
            f'background:{color};color:#111;font-weight:600;">{symbol} {status_value}</span>'
        )

    modules_html = []
    for module in report.modules:
        rows = []
        for check in module.checks:
            duration = f"{check.duration_ms:.0f} ms" if check.duration_ms else "-"
            rows.append(
                f"<tr><td>{esc(check.name)}</td><td>{status_badge(check.status.value)}</td>"
                f"<td>{esc(check.message)}</td><td>{duration}</td></tr>"
            )
        modules_html.append(f"""
        <div class="module-card">
            <h3>{esc(module.module_name)} {status_badge(module.overall_status.value)}</h3>
            <table>
                <thead><tr><th>Check</th><th>Status</th><th>Message</th><th>Duration</th></tr></thead>
                <tbody>{''.join(rows)}</tbody>
            </table>
        </div>
        """)

    interpretations_html = "".join(
        f'<li>{status_badge(i.severity.value)} &nbsp; {esc(i.text)}</li>' for i in report.interpretations
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Internet Connectivity &amp; Protocol Analyzer - Report</title>
<style>
    body {{ font-family: Segoe UI, Arial, sans-serif; background:#1e1f26; color:#eee; margin:0; padding:24px; }}
    h1 {{ color:#fff; }}
    .meta {{ color:#aaa; margin-bottom:24px; }}
    .info-grid {{ display:grid; grid-template-columns: repeat(3, 1fr); gap:10px; margin-bottom:30px; }}
    .info-box {{ background:#2a2c38; padding:12px 16px; border-radius:8px; }}
    .info-box .label {{ color:#999; font-size:12px; text-transform:uppercase; }}
    .info-box .value {{ font-size:16px; font-weight:600; margin-top:4px; }}
    .module-card {{ background:#25262f; border-radius:10px; padding:16px 20px; margin-bottom:18px; }}
    table {{ width:100%; border-collapse: collapse; margin-top:10px; }}
    th, td {{ text-align:left; padding:8px; border-bottom:1px solid #3a3c48; font-size:14px; }}
    th {{ color:#aaa; font-weight:500; }}
    ul.interp {{ list-style:none; padding:0; }}
    ul.interp li {{ background:#25262f; padding:10px 14px; border-radius:8px; margin-bottom:8px; }}
</style>
</head>
<body>
    <h1>Internet Connectivity &amp; Protocol Analyzer</h1>
    <div class="meta">Generated {report.generated_at:%Y-%m-%d %H:%M:%S}
        {f" &middot; Profile: {esc(report.profile_name)}" if report.profile_name else ""}
        {f" &middot; Duration: {report.duration_seconds:.0f} s" if report.duration_seconds else ""}</div>

    <div class="info-grid">
        <div class="info-box"><div class="label">Public IP</div><div class="value">{esc(info.public_ip or 'N/A')}</div></div>
        <div class="info-box"><div class="label">ISP</div><div class="value">{esc(info.isp or 'N/A')}</div></div>
        <div class="info-box"><div class="label">Location</div><div class="value">{esc(info.city or '')} {esc(info.country or '')}</div></div>
        <div class="info-box"><div class="label">IPv4 / IPv6</div><div class="value">{'✔' if info.ipv4_available else '✖'} / {'✔' if info.ipv6_available else '✖'}</div></div>
        <div class="info-box"><div class="label">Gateway</div><div class="value">{esc(info.gateway or 'N/A')}</div></div>
        <div class="info-box"><div class="label">DNS Servers</div><div class="value">{esc(', '.join(info.dns_servers) or 'N/A')}</div></div>
    </div>

    <h2>Test Results</h2>
    {''.join(modules_html)}

    <h2>Analysis (probabilistic interpretations, not definitive claims)</h2>
    <ul class="interp">{interpretations_html}</ul>
</body>
</html>"""


_EXPORTERS = {
    "txt": to_txt,
    "json": to_json,
    "csv": to_csv,
    "html": to_html,
}

_EXTENSIONS = {"txt": ".txt", "json": ".json", "csv": ".csv", "html": ".html"}


def save_report(report: FullReport, directory: Path, fmt: str, filename_prefix: str = "icpa_report") -> Path:
    """Render ``report`` in the given format and save it to ``directory``. Returns the file path."""
    fmt = fmt.lower()
    if fmt not in _EXPORTERS:
        raise ValueError(f"Unsupported export format: {fmt}")

    content = _EXPORTERS[fmt](report)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filepath = directory / f"{filename_prefix}_{timestamp}{_EXTENSIONS[fmt]}"

    directory.mkdir(parents=True, exist_ok=True)
    with open(filepath, "w", encoding="utf-8", newline="") as fh:
        fh.write(content)

    return filepath
