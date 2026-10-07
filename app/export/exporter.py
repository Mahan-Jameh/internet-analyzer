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
from typing import Optional

from app import i18n
from app.constants import STATUS_COLORS
from app.models import FullReport

_STATUS_SYMBOLS = {"OK": "✔", "WARNING": "⚠", "FAILED": "✖", "UNKNOWN": "?"}


_FINDING_SYMBOLS = {"ok": "✔", "warn": "⚠", "fail": "✖", "info": "ℹ"}


def _technical(check) -> str:  # noqa: ANN001 - CheckResult
    """One line of raw observation for layer 3 (never an interpretation)."""
    res = getattr(check, "result", None)
    if res is None:
        return ""
    parts = [res.status.value]
    if res.error_code:
        parts.append(f"code={res.error_code}")
    if res.platform_error is not None:
        parts.append(f"os_error={res.platform_error}")
    if res.attempts and res.attempts > 1:
        parts.append(f"attempts={res.attempts} ({res.retry_outcome.value})")
    if res.interpretation:
        conf = f" {res.confidence:.0%}" if res.confidence is not None else ""
        parts.append(f"interpretation={res.interpretation}{conf}")
    return " | ".join(parts)


def _diagnosis_lines(diag: dict, d) -> list[str]:  # noqa: ANN001
    """Layer 4: one diagnosis with its evidence, causes and caveat (all texts translatable)."""
    lines = [f"{d(diag['headline'])}  [{int(round(diag['confidence'] * 100))}%]"]
    lines += [f"    - {d('Evidence: ' + e)}" for e in diag["evidence"][:4]]
    if diag.get("possible_causes"):
        lines.append(f"    - {d('Possible causes: ' + '; '.join(diag['possible_causes'][:4]))}")
    if diag.get("caveats"):
        lines.append(f"    - {d('Note: ' + diag['caveats'][0])}")
    return lines


def _resolve_lang(lang: Optional[str]) -> str:
    return lang if lang in i18n.SUPPORTED_LANGUAGES else i18n.get_language()


def to_txt(report: FullReport, lang: Optional[str] = None) -> str:
    lang = _resolve_lang(lang)
    t = lambda text, *a: i18n.tr_fmt(text, *a, lang=lang)          # noqa: E731 - fixed phrases + values
    d = lambda text: i18n.translate_dynamic(text, lang)            # noqa: E731 - test / analyzer messages
    na = i18n.tr("N/A", lang)

    def yes_no(value: object) -> str:
        return i18n.tr("Yes" if value else "No", lang)

    lines: list[str] = []
    lines.append("=" * 70)
    lines.append(t("INTERNET CONNECTIVITY & PROTOCOL ANALYZER - REPORT"))
    lines.append("=" * 70)
    lines.append(t("Generated: {}", f"{report.generated_at:%Y-%m-%d %H:%M:%S}"))
    if report.profile_name:
        lines.append(t("Profile: {}", report.profile_name))
    lines.append("")

    lines.append(t("-- Network Information --"))
    info = report.network_info
    lines.append(t("Public IP     : {}", info.public_ip or na))
    lines.append(t("ISP           : {}", info.isp or na))
    lines.append(t("Country       : {}", info.country or na))
    lines.append(t("City          : {}", info.city or na))
    lines.append(t("IPv4 Available: {}", d(info.ipv4_state) if info.ipv4_state != "Unknown" else yes_no(info.ipv4_available)))
    lines.append(t("IPv6 Available: {}", d(info.ipv6_state) if info.ipv6_state != "Unknown" else yes_no(info.ipv6_available)))
    lines.append(t("DNS Servers   : {}", ", ".join(info.dns_servers) or na))
    lines.append(t("Adapter       : {}", info.adapter_name or na))
    lines.append(t("Gateway       : {}", info.gateway or na))
    lines.append(t("Internet OK   : {}", yes_no(info.internet_reachable)))
    lines.append("")

    layers = report.layers()
    # ---- layer 1 + 2: the short version ------------------------------------
    lines.append("=" * 70)
    lines.append("1. " + i18n.tr("Overall summary", lang))
    lines.append("=" * 70)
    overall = layers["overall_summary"]
    lines.append(f"  {overall['status']}: {d(overall['headline'])}")
    if layers["key_findings"]:
        lines.append("")
        lines.append("2. " + i18n.tr("Key findings", lang))
        for finding in layers["key_findings"]:
            lines.append(f"  {_FINDING_SYMBOLS.get(finding['symbol'], '?')} {d(finding['text'])}")
    lines.append("")

    # ---- layer 3: technical evidence ---------------------------------------
    lines.append("=" * 70)
    lines.append("3. " + i18n.tr("Technical evidence", lang))
    lines.append("=" * 70)
    for module in report.modules:
        lines.append("-" * 70)
        lines.append(t("MODULE: {}  [{}]", d(module.module_name),
                       i18n.tr_status(module.overall_status.value, lang)))
        lines.append("-" * 70)
        for check in module.checks:
            symbol = _STATUS_SYMBOLS.get(check.status.value, "?")
            duration = f" ({check.duration_ms:.0f} ms)" if check.duration_ms else ""
            lines.append(f"  {symbol} {d(check.name)}{duration}")
            if check.message:
                lines.append(f"      {d(check.message)}")
            technical = _technical(check)
            if technical:
                lines.append(f"      [{technical}]")
        lines.append("")

    # ---- layer 4: root cause -----------------------------------------------
    lines.append("=" * 70)
    lines.append("4. " + i18n.tr("Root cause analysis", lang) + " - "
                 + t("ANALYSIS / POSSIBLE INTERPRETATIONS (probabilistic, not definitive)"))
    lines.append("=" * 70)
    for diag in layers["root_cause"]:
        lines += [f"  {x}" for x in _diagnosis_lines(diag, d)]
    for interp in report.interpretations:
        symbol = _STATUS_SYMBOLS.get(interp.severity.value, "?")
        first, *rest = d(interp.text).split("\n")
        lines.append(f"  {symbol} {first}")
        lines += [f"      {x}" for x in rest]

    return "\n".join(lines)


def to_json(report: FullReport, lang: Optional[str] = None) -> str:
    """JSON always keeps the original English text so reports stay comparable and machine readable."""
    return json.dumps(report.to_dict(), indent=2, ensure_ascii=False)


def _csv_safe(text: str) -> str:
    """Stop spreadsheet programs from running text such as '=cmd|...' as a formula."""
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text


def _csv_technical(check) -> list[str]:  # noqa: ANN001
    res = getattr(check, "result", None)
    if res is None:
        return [""] * 6
    return [res.status.value, res.severity.value if res.severity else "", res.error_code or "",
            "" if res.platform_error is None else str(res.platform_error), res.interpretation or "",
            "" if res.confidence is None else f"{res.confidence:.2f}"]


def to_csv(report: FullReport, lang: Optional[str] = None) -> str:
    """Column headers and status values stay English (stable for scripts); texts follow ``lang``."""
    lang = _resolve_lang(lang)
    d = lambda text: i18n.translate_dynamic(text, lang)      # noqa: E731
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["Module", "Check", "Status", "Message", "Duration (ms)", "Timestamp",
                     "Technical Status", "Severity", "Error Code", "OS Error", "Interpretation", "Confidence"])
    for module in report.modules:
        for check in module.checks:
            writer.writerow([
                _csv_safe(d(module.module_name)),
                _csv_safe(d(check.name)),
                check.status.value,
                _csv_safe(d(check.message)),
                f"{check.duration_ms:.1f}" if check.duration_ms else "",
                check.timestamp.isoformat(),
                *_csv_technical(check),
            ])
    return buffer.getvalue()


def to_html(report: FullReport, lang: Optional[str] = None) -> str:
    lang = _resolve_lang(lang)
    rtl = i18n.is_rtl(lang)
    t = lambda text, *a: i18n.tr_fmt(text, *a, lang=lang)      # noqa: E731
    d = lambda text: i18n.translate_dynamic(text, lang)        # noqa: E731
    na = i18n.tr("N/A", lang)
    info = report.network_info

    def esc(value: object) -> str:
        """Everything that came from the network or a log is untrusted: escape it."""
        return html.escape("" if value is None else str(value))

    def status_badge(status_value: str) -> str:
        color = STATUS_COLORS.get(status_value, "#95a5a6")
        symbol = _STATUS_SYMBOLS.get(status_value, "?")
        return (
            f'<span style="display:inline-block;padding:2px 10px;border-radius:10px;'
            f'background:{color};color:#111;font-weight:600;">{symbol} {esc(i18n.tr_status(status_value, lang))}</span>'
        )

    modules_html = []
    for module in report.modules:
        rows = []
        for check in module.checks:
            duration = f"{check.duration_ms:.0f} ms" if check.duration_ms else "-"
            rows.append(
                f"<tr><td>{esc(d(check.name))}</td><td>{status_badge(check.status.value)}</td>"
                f"<td>{esc(d(check.message))}<div style='color:#8a8fa3;font-size:12px'><bdi>{esc(_technical(check))}</bdi></div></td><td>{duration}</td></tr>"
            )
        modules_html.append(f"""
        <div class="module-card">
            <h3>{esc(d(module.module_name))} {status_badge(module.overall_status.value)}</h3>
            <table>
                <thead><tr><th>{t('Check')}</th><th>{t('Status')}</th><th>{t('Message')}</th><th>{t('Duration')}</th></tr></thead>
                <tbody>{''.join(rows)}</tbody>
            </table>
        </div>
        """)

    interpretations_html = "".join(
        f'<li>{status_badge(i.severity.value)} &nbsp; '
        f'{"<br>".join(esc(d(line)) for line in i.text.split(chr(10)))}</li>' for i in report.interpretations
    )
    layers = report.layers()
    overall = layers["overall_summary"]
    findings_html = "".join(
        f'<li>{_FINDING_SYMBOLS.get(f["symbol"], "?")} {esc(d(f["text"]))}</li>' for f in layers["key_findings"])
    diagnoses_html = "".join(
        "<li><b>" + esc(d(g["headline"])) + f' ({int(round(g["confidence"] * 100))}%)</b><ul>'
        + "".join(f"<li>{esc(d('Evidence: ' + e))}</li>" for e in g["evidence"][:4])
        + (f"<li>{esc(d('Possible causes: ' + '; '.join(g['possible_causes'][:4])))}</li>" if g.get("possible_causes") else "")
        + (f"<li>{esc(d('Note: ' + g['caveats'][0]))}</li>" if g.get("caveats") else "")
        + "</ul></li>" for g in layers["root_cause"])

    return f"""<!DOCTYPE html>
<html lang="{lang}" dir="{'rtl' if rtl else 'ltr'}">
<head>
<meta charset="utf-8">
<title>{esc(t('Internet Connectivity & Protocol Analyzer - Report'))}</title>
<style>
    body {{ font-family: 'Google Sans', 'Vazirmatn', 'Segoe UI', Tahoma, Arial, sans-serif; background:#1e1f26; color:#eee; margin:0; padding:24px; }}
    h1 {{ color:#fff; }}
    .meta {{ color:#aaa; margin-bottom:24px; }}
    .info-grid {{ display:grid; grid-template-columns: repeat(3, 1fr); gap:10px; margin-bottom:30px; }}
    .info-box {{ background:#2a2c38; padding:12px 16px; border-radius:8px; }}
    .info-box .label {{ color:#999; font-size:12px; text-transform:uppercase; }}
    .info-box .value {{ font-size:16px; font-weight:600; margin-top:4px; }}
    .module-card {{ background:#25262f; border-radius:10px; padding:16px 20px; margin-bottom:18px; }}
    table {{ width:100%; border-collapse: collapse; margin-top:10px; }}
    th, td {{ text-align:start; padding:8px; border-bottom:1px solid #3a3c48; font-size:14px; }}
    th {{ color:#aaa; font-weight:500; }}
    ul.interp {{ list-style:none; padding:0; }}
    ul.interp li {{ background:#25262f; padding:10px 14px; border-radius:8px; margin-bottom:8px; }}
</style>
</head>
<body>
    <h1>{esc(t('Internet Connectivity & Protocol Analyzer'))}</h1>
    <div class="meta">{esc(t('Generated'))} <bdi>{report.generated_at:%Y-%m-%d %H:%M:%S}</bdi>
        {f" &middot; {esc(t('Profile: {}', report.profile_name))}" if report.profile_name else ""}
        {f" &middot; {esc(t('Duration: {} s', f'{report.duration_seconds:.0f}'))}" if report.duration_seconds else ""}</div>

    <div class="info-grid">
        <div class="info-box"><div class="label">{esc(i18n.tr('Public IP', lang))}</div><div class="value"><bdi>{esc(info.public_ip or na)}</bdi></div></div>
        <div class="info-box"><div class="label">{esc(i18n.tr('ISP', lang))}</div><div class="value">{esc(info.isp or na)}</div></div>
        <div class="info-box"><div class="label">{esc(t('Location'))}</div><div class="value">{esc(info.city or '')} {esc(info.country or '')}</div></div>
        <div class="info-box"><div class="label">IPv4 / IPv6</div><div class="value"><bdi>{esc(d(info.ipv4_state) if info.ipv4_state != 'Unknown' else ('✔' if info.ipv4_available else '✖'))} / {esc(d(info.ipv6_state) if info.ipv6_state != 'Unknown' else ('✔' if info.ipv6_available else '✖'))}</bdi></div></div>
        <div class="info-box"><div class="label">{esc(i18n.tr('Gateway', lang))}</div><div class="value"><bdi>{esc(info.gateway or na)}</bdi></div></div>
        <div class="info-box"><div class="label">{esc(i18n.tr('DNS Servers', lang))}</div><div class="value"><bdi>{esc(', '.join(info.dns_servers) or na)}</bdi></div></div>
    </div>

    <h2>1. {esc(i18n.tr('Overall summary', lang))}</h2>
    <div class="module-card"><b>{esc(overall['status'])}</b> &mdash; {esc(d(overall['headline']))}</div>
    <h2>2. {esc(i18n.tr('Key findings', lang))}</h2>
    <ul class="interp">{findings_html}</ul>

    <h2>3. {esc(i18n.tr('Technical evidence', lang))}</h2>
    {''.join(modules_html)}

    <h2>4. {esc(i18n.tr('Root cause analysis', lang))}</h2>
    <ul class="interp">{diagnoses_html}</ul>
    <h2>{esc(t('Analysis (probabilistic interpretations, not definitive claims)'))}</h2>
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


def save_report(report: FullReport, directory: Path, fmt: str, filename_prefix: str = "icpa_report",
                lang: Optional[str] = None) -> Path:
    """
    Render ``report`` in the given format and save it to ``directory``. Returns the file path.
    ``lang`` defaults to the language currently selected in the app.
    """
    fmt = fmt.lower()
    if fmt not in _EXPORTERS:
        raise ValueError(f"Unsupported export format: {fmt}")

    content = _EXPORTERS[fmt](report, lang)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filepath = directory / f"{filename_prefix}_{timestamp}{_EXTENSIONS[fmt]}"

    directory.mkdir(parents=True, exist_ok=True)
    # CSV gets a byte-order mark so Excel reads Persian text correctly.
    encoding = "utf-8-sig" if fmt == "csv" else "utf-8"
    with open(filepath, "w", encoding=encoding, newline="") as fh:
        fh.write(content)

    return filepath
