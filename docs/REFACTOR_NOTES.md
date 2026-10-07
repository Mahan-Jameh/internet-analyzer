# Refactor notes (schema v2)

This release replaces boolean-style results with a layered model. Nothing was removed from the
user interface: the GUI still shows **OK / WARNING / FAILED**.

## What changed

| Area | Before | Now |
|---|---|---|
| Result | `CheckResult(status OK/WARNING/FAILED)` | `TestResult` (technical status, severity, error code, OS error, attempts, retry outcome, interpretation + confidence, evidence) carried inside `CheckResult.result` |
| TCP | open / closed / filtered by guess | `OPEN`, `CLOSED` (refused), `TIMEOUT`, `RESET`, `UNREACHABLE`; a timeout is *never* reported as closed |
| UDP | silence = open | protocol-aware probes (DNS/NTP); silence = `OPEN_OR_FILTERED` (inconclusive); ICMP port-unreachable = `CLOSED` |
| IPv4/IPv6 | two booleans | four layers each (address, route, DNS, TCP); GUI shows *Not configured* / *Configured, but no Internet access* / *Available* |
| Public IP | decided "online" | auxiliary lookup; failure is `INFO`, never "Internet down" |
| ICMP | ping failed = problem | ICMP silence is `INFO` (many hosts drop echo) |
| TLS | one error string | phases: DNS, TCP, ClientHello/handshake, certificate; SNI vs no-SNI comparison |
| Sites | first failing stage | DNS → TCP → TLS → HTTP chain, downstream layers marked `SKIPPED`, control comparison kept |
| Proxy/VPN | warning | *evidence* (`INFO`, `metadata.detected`); installed-but-disconnected adapters and VM adapters are not VPN diagnoses |
| Execution | sequential | dependency graph, bounded concurrency, exclusive measurement modules, real cancellation |
| Analysis | name-substring rules | correlation engine (by category/role) + legacy detail lines that are suppressed when the engine already explained the same thing |
| Report | flat list | 4 layers: overall summary, key findings, technical evidence, root cause |
| History | v1 JSON | `schema_version: 2` (v1 keys kept, new keys `run`, `tests`, `diagnoses`, `summary`, `key_findings`) |

## Compatibility

* **Reading old files:** `app.export.history.normalize_report_dict` upgrades any v1 file on load
  (empty `tests`/`diagnoses`, a `run` block rebuilt from the top-level fields). Unknown future keys are kept.
* **Writing:** all v1 top-level keys are still written, so older readers keep working.
* **Compare:** network fields present in only one of two reports (v1 vs v2) are not reported as changes.
* **CSV:** the first six columns are unchanged; technical columns were appended.
* **Module names / check names** used by the GUI and the legacy analyzer are unchanged.
* New module key `local_network` ("Local Network & Gateway"); it is part of the default run.

## Configuration

`app/diag/testconfig.py` (`NetworkTestConfig`) is the single place for timeouts, the retry policy,
concurrency and target groups. Retries apply only to transient outcomes (timeout, reset, temporary
DNS failure, TLS handshake reset/timeout) - never to refusals, NXDOMAIN or certificate errors.
Default `latency_probes` is 10 per target (was 20) to keep a full run short.

## Logging

`icpa_YYYYMMDD.log` stays human readable. `icpa_YYYYMMDD.jsonl` holds one JSON object per record; each
test result also has a `TEST RESULT key=value ...` line (no free text, no headers, no bodies).
The run summary line still contains your public IP, as before, in your *local* log only.

## Limits that cannot be removed from a client-side tool

* A timeout cannot tell a filter from packet loss or an outage; it is reported with a confidence value.
* ICMP, UDP and gateway silence are normal on many networks and are reported as inconclusive.
* SNI/ClientHello inspection, TLS interception and DNS tampering can only be *suggested*, never proven.
* Proxy/VPN detection reads local settings and adapter names; it cannot see a transparent proxy.
* Windows-specific parsing (`route print`, `ipconfig`, `netsh`) was written to be language-independent
  but was verified against sample output, not on live Windows machines (see the final report).
