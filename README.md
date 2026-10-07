# Internet Connectivity & Protocol Analyzer

A desktop diagnostic tool for ordinary users, built with **Python 3.12+**
and **PySide6**, that helps you understand why your Internet connection
might be slow, restricted, or partially blocked - without any networking
knowledge required.

> **Scope note:** this tool only ever *diagnoses*. It never attempts to
> bypass any restriction, and it never states a definitive censorship
> claim - only hedged, probabilistic interpretations of what was observed.

---

## Features

- **Home screen** - public IP, ISP, country/city, IPv4/IPv6 availability,
  DNS servers, network adapter, gateway, overall Internet status.
- **Proxy & VPN Detection** - checks for a system proxy, programs listening
  on common local proxy ports, and VPN/TUN adapters. If a tunnel is active,
  every other result describes the tunnel, and the report says so.
- **Basic Connectivity** - ping, traceroute, DNS resolution, HTTP/HTTPS request.
- **DNS Test** - queries Google / Cloudflare / Quad9 / OpenDNS directly,
  plus the system resolver and DNS-over-HTTPS, then looks for an *outlier*
  resolver or block-page style (private/loopback) answers.
- **TCP Port Scanner** - restricted to a fixed allow-list of well known ports;
  reports open / closed / filtered / timeout / reset with latency.
- **UDP Test** - reachability probing on 53 / 123 / 443 / 500 / 4500 / 51820.
- **TLS Test** - TLS 1.2 / 1.3, certificate validation, handshake time, SNI,
  ALPN, cipher suite, and an **SNI filtering probe** (same server, different
  SNI names).
- **HTTP Test** - HTTP, HTTPS, HTTP/2, HTTP/3 (QUIC), redirects, compression,
  real keep-alive check, and **block page detection** (HTTP 451, redirects or
  iframes to private addresses).
- **TCP Stall Test** - detects connections that start fine and die after
  roughly 10-40 KB (the "16-20 KB" pattern).
- **Website Reachability** - checks sites layer by layer (DNS, TCP, TLS,
  HTTPS) and reports the first layer that fails, compared with control sites.
  The site list can be your own (Advanced tab).
- **Protocol Tests** - QUIC transport, DoH, DoT, ICMP, WebSocket.
- **Latency Test** - multi-target ping: average, packet loss, jitter.
- **MTU Test** - path MTU estimate via DF-flagged ping binary search.
- **VPN-Related Connectivity** - raw reachability of common VPN transport ports
  only; never connects to a VPN or claims one "works".
- **Protocol Whitelist Probe (optional, off by default)** - looks for a filter
  that only lets recognisable protocols through on port 443. It can make a
  filter drop your packets for about a minute, so it asks for confirmation.
- **Analysis engine** - plain-language, probability-worded interpretations
  ("may", "could indicate", "consistent with"), including what *is* working.
- **Diagnostics tab** - choose which tests to run, repeat a run N times with a
  pause, stop at any time; gray cards show tests that are waiting or not run.
- **History tab** - every finished run is saved automatically; compare any two
  runs (which checks improved or got worse, and what changed in your network).
- **Export** - TXT, JSON, CSV, and a self-contained HTML report
  (untrusted text is escaped; CSV cells cannot run as spreadsheet formulas).
- **Advanced mode** - custom target host, ports, website list, saved profiles.
- **Logging** - daily log files plus a per-run summary line (timestamp,
  duration, errors, network info).
- Runs without administrator privileges. Every module is isolated: a failure
  becomes an UNKNOWN result instead of crashing the app.

---

## Project structure

```
internet_analyzer/
├── main.py                      Entry point
├── requirements.txt / requirements-dev.txt
├── build.spec                   PyInstaller spec
├── tests/                       pytest suite (no network needed)
└── app/
    ├── constants.py             All fixed values (ports, timeouts, URLs, hosts)
    ├── config.py                Paths + persisted settings
    ├── logger.py                File + in-memory logging
    ├── models.py                Shared dataclasses
    ├── core/                    All test logic (no widgets)
    │   ├── network_info.py  environment_check.py  basic_connectivity.py
    │   ├── dns_test.py  tcp_scanner.py  udp_test.py  tls_test.py  http_test.py
    │   ├── tcp_stall_test.py  site_reachability.py  protocol_tests.py
    │   ├── latency_test.py  mtu_test.py  vpn_connectivity.py
    │   ├── protocol_whitelist.py
    │   ├── analyzer.py          Results -> hedged interpretations
    │   ├── compare.py           Compare two saved reports
    │   └── worker.py            QThread runner (cancel, run summary logging)
    ├── gui/                     PySide6 UI (Home, Diagnostics, Advanced, History, Logs)
    ├── export/                  exporter.py (TXT/JSON/CSV/HTML), history.py
    └── utils/helpers.py         subprocess wrapper, language-independent ping parser,
                                 target host validation
```

---

## Running from source

```bash
python -m venv venv
venv\Scripts\activate          # Windows
pip install -r requirements.txt
python main.py
```

Run the tests (they need no Internet):

```bash
pip install -r requirements-dev.txt
pytest
```

Requires **Python 3.12+**. Target platforms: **Windows 10 and Windows 11**.

## Building a standalone .exe

```bash
pip install -r requirements.txt
pyinstaller build.spec
```

The output is `dist/ICPA/ICPA.exe`. All application data (logs, reports,
history, profiles, settings) lives under `%LOCALAPPDATA%\ICPA`, never next to
the executable.

---

## Design notes

- **Diagnose, never bypass.** No circumvention code is included. The SNI,
  stall and whitelist probes only *observe* how connections behave.
- **Hedged wording.** A single client-side test cannot prove intent, so every
  interpretation says "may", "consistent with" or "a possibility".
- **Control comparisons.** Per-site results are only meaningful if control
  sites work, so the report compares them and says when they fail too.
- **Language-independent parsing.** Windows translates the word "time" in
  `ping` output (and some error texts). Replies are recognised by their `TTL=`
  marker instead, so results are correct on non-English Windows.
- **User input is validated** before it reaches `ping`/`tracert` (no leading
  `-`, no spaces) and port selection is limited to fixed allow-lists.
- **TCP scanning** only targets a few always-on anycast hosts or the host you
  enter; it is a reachability check, not a general port scanner.
- **HTTP/3** uses a real QUIC handshake when `aioquic` is installed, otherwise
  an `Alt-Svc` hint labelled as such.
- **Threads** are stopped and awaited when the window closes.

## Sources and acknowledgements

Methodology ideas were taken from public projects and research. No code or
domain lists were copied; all code here is original.

- [Runnin4ik/dpi-detector](https://github.com/Runnin4ik/dpi-detector) (MIT) -
  the idea of a TCP 16-20 KB stall test and of separating error types.
- [MayersScott/rkn-block-checker](https://github.com/MayersScott/rkn-block-checker)
  (MIT) - layered DNS/TCP/TLS/HTTP checks, system-resolver vs DoH comparison,
  "TCP works but TLS fails" as a sign of ClientHello inspection.
- [OONI Probe](https://github.com/ooni/probe) - the reference for open
  network measurement.
- Bock et al., *Detecting and Evading Censorship-in-Depth: A Case Study of
  Iran's Protocol Filter* (FOCI 2020) - the basis of the optional protocol
  whitelist probe. Behaviour may have changed since the study.
- [bepass-org/oblivion-desktop](https://github.com/bepass-org/oblivion-desktop/wiki/Ports-Used-by-the-Application)
  - documented local ports (8086, 8087, 50051) used by the proxy detection.

## License

Provided as-is for personal diagnostic use.
