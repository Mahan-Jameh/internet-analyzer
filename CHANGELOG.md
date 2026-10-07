# Changelog

## 2.0.1
- Persian: multi-line analysis texts are now translated line by line (a template could swallow a whole
  multi-line text and leave it in English); added missing translations (key-finding labels such as
  "Local gateway", site lists, SNI probe outcomes, causes).
- Stricter translation test that flags leftover English words, not only long English runs.

## 2.0.0 - layered diagnostics
- New result model: raw technical status vs. severity vs. interpretation with confidence.
- TCP states (TIMEOUT is never CLOSED), protocol-aware UDP, layered IPv4/IPv6, public IP as auxiliary only.
- New: Local Network & Gateway module, DNS layers, TLS phases + SNI comparison, layered HTTP and site reachability.
- Proxy/VPN detection reports evidence only (never a failure).
- Dependency-graph runner: parallel modules, SKIPPED/BLOCKED states, real cancellation, centralized config, selective retries.
- Correlation / root-cause engine; four-layer report; JSON history `schema_version: 2` (v1 files still load).
- Windows error normalization (WSA codes), structured logging (`.log` + `.jsonl`), Persian translation of all new messages.
- Bundled fonts: Vazirmatn (Persian) and Google Sans (English). `run.bat` launcher.
- See `docs/REFACTOR_NOTES.md`.

## 1.0.0 - first complete version
- Connectivity, DNS, TCP/UDP, TLS, HTTP/2/3, QUIC, DoH/DoT, ICMP, WebSocket, latency, MTU and VPN-port tests.
- Probabilistic analyzer, TXT/JSON/CSV/HTML export, history and compare, advanced mode, Persian RTL UI.
