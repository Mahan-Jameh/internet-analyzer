"""
dns_test.py
===========
DNS diagnostics split into layers, so "DNS failed" always says *which* layer:

    1. local DNS configuration        which servers does this machine use?
    2. DNS server reachability        does the server answer at all (UDP, then TCP)?
    3. name resolution                per resolver and per domain, with the real DNS
                                      outcome (RESOLVED / NXDOMAIN / SERVFAIL / REFUSED /
                                      TIMEOUT / NETWORK_ERROR)
    4. resolution through several     public resolvers, the configured servers, the OS
       resolvers                      resolver and (optionally) DNS-over-HTTPS
    5. answer comparison              outlier / block-page style answers

A server that does not answer its first query is not asked the remaining domains
(they are reported as SKIPPED, blocked by the server) - no cascade of identical
timeouts. The module only observes; filtering is never declared as a fact.
"""

from __future__ import annotations

import ipaddress
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from typing import Optional

import dns.exception
import dns.message
import dns.query
import dns.rcode
import httpx

from app.constants import DNS_RESOLVERS, DNS_TEST_DOMAINS, DOH_ENDPOINTS
from app.diag.adapter import check_from_result
from app.diag.localnet import dns_servers as configured_dns_servers
from app.diag.neterrors import normalize_exception
from app.diag.results import RetryOutcome, Severity, TechnicalStatus, TestResult
from app.diag.retry import run_with_retry
from app.diag.testconfig import DEFAULT_CONFIG, NetworkTestConfig
from app.logger import get_logger
from app.models import CheckResult, ModuleReport, Status

log = get_logger(__name__)
_S = TechnicalStatus

SYSTEM_RESOLVER_NAME = "System"
MAX_CONFIGURED_SERVERS = 3

# DNS outcomes (test matrix) -> technical status
OUTCOME_STATUS = {
    "RESOLVED": _S.SUCCESS, "NXDOMAIN": _S.DNS_FAILED, "SERVFAIL": _S.DNS_FAILED, "NO_DATA": _S.DNS_FAILED,
    "TIMEOUT": _S.TIMEOUT, "REFUSED": _S.REFUSED, "NETWORK_ERROR": _S.UNREACHABLE,
}


def is_suspicious_answer(ip: str) -> bool:
    """
    True if ``ip`` is an address that a public domain should never resolve to:
    private (RFC 1918), loopback, unspecified or link-local. Filtering systems
    often answer blocked names with such addresses (block pages).
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_private or addr.is_loopback or addr.is_unspecified or addr.is_link_local


def _is_public_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def query_server(server: str, domain: str, timeout: float) -> tuple[str, list[str], float, Optional[str], bool]:
    """
    Ask one DNS server for an A record. Returns (outcome, answers, elapsed_ms, error_text, used_tcp).
    ``used_tcp`` is True when the answer was truncated over UDP and TCP was used (RFC 7766).
    """
    start = time.perf_counter()
    try:
        message = dns.message.make_query(domain, "A")
        response, used_tcp = dns.query.udp_with_fallback(message, server, timeout=timeout)
    except dns.exception.Timeout:
        return "TIMEOUT", [], (time.perf_counter() - start) * 1000.0, "no UDP answer", False
    except (OSError, dns.exception.DNSException) as exc:
        norm = normalize_exception(exc)
        outcome = "TIMEOUT" if norm.error_code == "TIMEOUT" else "NETWORK_ERROR"
        return outcome, [], (time.perf_counter() - start) * 1000.0, norm.error_code, False
    elapsed = (time.perf_counter() - start) * 1000.0
    rcode = response.rcode()
    answers = sorted(str(r) for rrset in response.answer if rrset.rdtype == 1 for r in rrset)
    if rcode == dns.rcode.NXDOMAIN:
        return "NXDOMAIN", [], elapsed, None, used_tcp
    if rcode == dns.rcode.SERVFAIL:
        return "SERVFAIL", [], elapsed, None, used_tcp
    if rcode == dns.rcode.REFUSED:
        return "REFUSED", [], elapsed, None, used_tcp
    if rcode != dns.rcode.NOERROR:
        return "SERVFAIL", [], elapsed, f"rcode {dns.rcode.to_text(rcode)}", used_tcp
    return ("RESOLVED" if answers else "NO_DATA"), answers, elapsed, None, used_tcp


def tcp_reachable(server: str, domain: str, timeout: float) -> bool:
    try:
        dns.query.tcp(dns.message.make_query(domain, "A"), server, timeout=timeout)
        return True
    except (OSError, dns.exception.DNSException):
        return False


class DNSTester:
    def __init__(self, config: NetworkTestConfig = DEFAULT_CONFIG, cancel: Optional[threading.Event] = None,
                 domains: Optional[list[str]] = None, resolvers: Optional[dict[str, str]] = None,
                 configured_servers: Optional[list[str]] = None, system_lookup=None,  # noqa: ANN001
                 query=query_server, tcp_check=tcp_reachable, include_doh: bool = True) -> None:
        self.config = config
        self.cancel = cancel or threading.Event()
        self.domains = domains or list(DNS_TEST_DOMAINS)
        self.resolvers = dict(resolvers if resolvers is not None else DNS_RESOLVERS)
        self._configured = configured_servers
        self._system_lookup = system_lookup or self._getaddrinfo
        self._query, self._tcp_check = query, tcp_check
        self.include_doh = include_doh

    # ---- layer 1: configuration ------------------------------------------
    def check_configuration(self, servers: list[str]) -> TestResult:
        res = TestResult("dns.config", "dns_config", protocol="DNS", metrics={"servers": servers})
        if servers:
            res.status = _S.SUCCESS
            res.summary = f"{len(servers)} DNS server(s) configured: {', '.join(servers[:4])}."
            res.add_evidence("Configured servers: " + ", ".join(servers))
        else:
            res.status, res.severity = _S.INCONCLUSIVE, Severity.INFO
            res.summary = "The configured DNS servers could not be determined on this system."
        return res

    # ---- layers 2+3: one server -----------------------------------------------
    def probe_server(self, name: str, server: str, role: str) -> tuple[TestResult, list[TestResult], dict[str, list[str]]]:
        """Reachability of one server and resolution of every test domain through it."""
        timeout = self.config.dns_timeout
        server_id = f"dns.server.{name}"
        results: list[TestResult] = []
        answers: dict[str, list[str]] = {}
        srv = TestResult(server_id, "dns_server", target=server, protocol="DNS", port=53,
                         timeout_ms=int(timeout * 1000), metadata={"role": role, "name": name},
                         metrics={"udp_ok": None, "tcp_ok": None, "resolved": 0, "domains": len(self.domains)})
        started = time.perf_counter()

        def first_probe(n: int) -> TestResult:
            outcome, ans, elapsed, why, used_tcp = self._query(server, self.domains[0], timeout)
            r = self._resolution_result(name, server, self.domains[0], role, outcome, ans, elapsed, why, used_tcp)
            r.metadata["attempt"] = n
            r.error_code = None if outcome == "RESOLVED" else outcome
            return r

        first = run_with_retry(first_probe, self.config.retry, self.cancel)
        results.append(first)
        answers[self.domains[0]] = first.metadata.get("addresses", [])
        reachable = first.metadata["dns_outcome"] in ("RESOLVED", "NXDOMAIN", "SERVFAIL", "REFUSED", "NO_DATA")
        srv.metrics["udp_ok"] = reachable
        srv.attempts, srv.retry_outcome = first.attempts, first.retry_outcome

        if not reachable:
            # Layer 4 of the question "why": is it UDP specifically, or the server as a whole?
            srv.metrics["tcp_ok"] = self._tcp_check(server, self.domains[0], timeout)
            if srv.metrics["tcp_ok"]:
                srv.status, srv.severity = _S.PARTIAL, Severity.WARNING
                srv.interpretation, srv.confidence = "UDP_DNS_BLOCKED_TCP_WORKS", 0.7
                srv.summary = f"{name} ({server}): UDP DNS is silent but TCP DNS answers."
                srv.add_evidence("UDP/53 query got no answer; TCP/53 query succeeded.")
            else:
                srv.status = first.status if first.status in (_S.TIMEOUT, _S.UNREACHABLE) else _S.TIMEOUT
                srv.error_code = first.metadata["dns_outcome"]
                srv.interpretation, srv.confidence = "SERVER_UNREACHABLE_OR_FILTERED", 0.5
                srv.summary = f"{name} ({server}): no DNS answer over UDP or TCP."
                srv.add_evidence("Neither UDP/53 nor TCP/53 produced a DNS answer.")
            for domain in self.domains[1:]:
                skipped = TestResult(f"dns.resolve.{name}.{domain}", "dns_resolution", status=_S.SKIPPED,
                                     target=domain, protocol="DNS",
                                     metadata={"role": role, "domain": domain, "resolver": name,
                                               "skip_reason": "BLOCKED_BY_DEPENDENCY", "blocked_by": [server_id]})
                results.append(skipped)
                answers[domain] = []
        else:
            for domain in self.domains[1:]:
                if self.cancel.is_set():
                    break
                outcome, ans, elapsed, why, used_tcp = self._query(server, domain, timeout)
                results.append(self._resolution_result(name, server, domain, role, outcome, ans, elapsed, why, used_tcp))
                answers[domain] = ans
            resolved = sum(1 for r in results if r.ok)
            srv.metrics["resolved"] = resolved
            srv.status = _S.SUCCESS if resolved == len(self.domains) else (_S.PARTIAL if resolved else _S.DNS_FAILED)
            srv.severity = {_S.SUCCESS: Severity.OK, _S.PARTIAL: Severity.WARNING}.get(srv.status, Severity.ERROR)
            srv.summary = (f"{name} ({server}): reachable; {resolved}/{len(self.domains)} domains resolved."
                           if resolved else f"{name} ({server}): reachable, but no domain resolved "
                           f"({first.metadata['dns_outcome']}).")
            srv.add_evidence(f"The server answered DNS queries ({resolved} of {len(self.domains)} resolved)")
        srv.duration_ms = (time.perf_counter() - started) * 1000.0
        return srv, results, answers

    def _resolution_result(self, resolver: str, server: str, domain: str, role: str, outcome: str,
                           answers: list[str], elapsed: float, why: Optional[str], used_tcp: bool) -> TestResult:
        res = TestResult(f"dns.resolve.{resolver}.{domain}", "dns_resolution",
                         status=OUTCOME_STATUS.get(outcome, _S.ERROR), target=domain, protocol="DNS",
                         port=53, resolved_ip=answers[0] if answers else None, duration_ms=elapsed,
                         timeout_ms=int(self.config.dns_timeout * 1000),
                         metadata={"role": role, "domain": domain, "resolver": resolver, "server": server,
                                   "dns_outcome": outcome, "addresses": answers, "used_tcp": used_tcp})
        if outcome != "RESOLVED":
            res.error_code = outcome
            res.error_message = why
        if outcome == "RESOLVED":
            res.summary = f"{domain} -> {', '.join(answers[:3])} via {resolver}"
            res.add_evidence(f"{resolver} returned {len(answers)} address(es) for {domain}")
        else:
            res.summary = f"{resolver} could not resolve {domain}: {outcome}"
            res.add_evidence(f"{resolver} answered {outcome} for {domain}")
        if any(is_suspicious_answer(a) for a in answers):
            res.metadata["suspicious_answer"] = True
            res.warnings.append("The answer is a private/loopback address, typical of a block page.")
        return res

    # ---- the operating-system resolver ------------------------------------------
    @staticmethod
    def _getaddrinfo(domain: str) -> list[str]:
        infos = socket.getaddrinfo(domain, None, socket.AF_INET)
        return sorted({i[4][0] for i in infos})

    def probe_system(self) -> tuple[TestResult, list[TestResult], dict[str, list[str]]]:
        timeout = self.config.dns_timeout
        results: list[TestResult] = []
        answers: dict[str, list[str]] = {}
        pool = ThreadPoolExecutor(max_workers=len(self.domains), thread_name_prefix="icpa-sysdns")
        started = time.perf_counter()
        futures = {d: pool.submit(self._timed_lookup, d) for d in self.domains}
        for domain, fut in futures.items():
            try:
                ips, elapsed, exc = fut.result(timeout=timeout + 1.0)
            except FutureTimeout:
                ips, elapsed, exc = [], timeout * 1000.0, TimeoutError("lookup timed out")
            res = TestResult(f"dns.resolve.{SYSTEM_RESOLVER_NAME}.{domain}", "dns_resolution", target=domain,
                             protocol="DNS", duration_ms=elapsed, timeout_ms=int(timeout * 1000),
                             metadata={"role": "system", "domain": domain, "resolver": SYSTEM_RESOLVER_NAME,
                                       "addresses": ips})
            if ips:
                res.status, res.resolved_ip = _S.SUCCESS, ips[0]
                res.metadata["dns_outcome"] = "RESOLVED"
                res.summary = f"{domain} -> {', '.join(ips[:3])} via the system resolver"
                if any(is_suspicious_answer(a) for a in ips):
                    res.metadata["suspicious_answer"] = True
                    res.warnings.append("The answer is a private/loopback address, typical of a block page.")
            else:
                norm = normalize_exception(exc) if exc else None
                res.status = norm.status if norm and norm.status in (_S.TIMEOUT, _S.DNS_FAILED) else _S.DNS_FAILED
                res.error_type = norm.error_type if norm else None
                res.error_code = norm.error_code if norm else "NO_ANSWER"
                res.platform_error = norm.platform_error if norm else None
                res.error_message = norm.error_message if norm else None
                res.metadata["dns_outcome"] = "TIMEOUT" if res.status is _S.TIMEOUT else "NXDOMAIN" \
                    if res.error_code == "HOST_NOT_FOUND" else "NETWORK_ERROR"
                res.summary = f"The system resolver could not resolve {domain} ({res.error_code})."
                res.add_evidence(f"getaddrinfo({domain}) failed with {res.error_code}")
            results.append(res)
            answers[domain] = ips
        pool.shutdown(wait=False)
        resolved = sum(1 for r in results if r.ok)
        srv = TestResult("dns.server.System", "dns_server", protocol="DNS",
                         metadata={"role": "system", "name": SYSTEM_RESOLVER_NAME},
                         metrics={"resolved": resolved, "domains": len(self.domains)},
                         duration_ms=(time.perf_counter() - started) * 1000.0)
        if resolved == len(self.domains):
            srv.status, srv.summary = _S.SUCCESS, f"All {len(self.domains)} test domains resolved by the system DNS."
        elif resolved:
            srv.status, srv.severity = _S.PARTIAL, Severity.WARNING
            srv.summary = f"Only {resolved}/{len(self.domains)} domains resolved by the system DNS."
        else:
            srv.status = _S.DNS_FAILED
            srv.summary = "The system DNS could not resolve any test domain."
            srv.interpretation = "SYSTEM_RESOLVER_FAILING"
        return srv, results, answers

    def _timed_lookup(self, domain: str) -> tuple[list[str], float, Optional[BaseException]]:
        start = time.perf_counter()
        try:
            return list(self._system_lookup(domain)), (time.perf_counter() - start) * 1000.0, None
        except (OSError, UnicodeError) as exc:
            return [], (time.perf_counter() - start) * 1000.0, exc

    # ---- optional: DNS over HTTPS --------------------------------------------------
    def probe_doh(self) -> tuple[TestResult, list[TestResult], dict[str, list[str]]]:
        endpoint = DOH_ENDPOINTS["Cloudflare"]
        name = "Cloudflare DoH"
        results: list[TestResult] = []
        answers: dict[str, list[str]] = {}
        started = time.perf_counter()
        for domain in self.domains:
            if self.cancel.is_set():
                break
            t0 = time.perf_counter()
            res = TestResult(f"dns.resolve.{name}.{domain}", "dns_resolution", target=domain, protocol="DoH",
                             metadata={"role": "doh", "domain": domain, "resolver": name})
            try:
                resp = httpx.get(endpoint, params={"name": domain, "type": "A"},
                                 headers={"accept": "application/dns-json"}, timeout=self.config.dns_timeout + 2)
                ips = sorted(str(a["data"]) for a in resp.json().get("Answer", []) if a.get("type") == 1)
                res.status = _S.SUCCESS if ips else _S.DNS_FAILED
                res.error_code = None if ips else "NO_DATA"
                res.metadata.update(addresses=ips, dns_outcome="RESOLVED" if ips else "NO_DATA")
                answers[domain] = ips
            except (httpx.HTTPError, ValueError, KeyError, TypeError) as exc:
                norm = normalize_exception(exc)
                res.status = _S.TIMEOUT if norm.error_code == "TIMEOUT" else _S.UNREACHABLE
                res.error_code, res.error_message = norm.error_code, norm.error_message
                res.metadata.update(addresses=[], dns_outcome="NETWORK_ERROR")
                answers[domain] = []
            res.duration_ms = (time.perf_counter() - t0) * 1000.0
            res.summary = f"{domain} via DoH: {res.status.value}"
            results.append(res)
        resolved = sum(1 for r in results if r.ok)
        srv = TestResult("dns.server.DoH", "dns_server", target=endpoint, protocol="DoH",
                         metadata={"role": "doh", "name": name}, severity=Severity.INFO,
                         metrics={"resolved": resolved, "domains": len(self.domains)},
                         duration_ms=(time.perf_counter() - started) * 1000.0)
        srv.status = _S.SUCCESS if resolved == len(self.domains) else (_S.PARTIAL if resolved else _S.INCONCLUSIVE)
        srv.severity = Severity.OK if srv.status is _S.SUCCESS else Severity.WARNING if resolved else Severity.INFO
        srv.summary = (f"{resolved}/{len(self.domains)} domains resolved over HTTPS." if resolved else
                       "DNS-over-HTTPS could not be used, so it is not part of the comparison.")
        return srv, results, answers

    # ---- run --------------------------------------------------------------------------
    def run_all(self) -> ModuleReport:
        report = ModuleReport(module_name="DNS Test")
        servers = self._configured if self._configured is not None else configured_dns_servers()
        cfg_result = self.check_configuration(servers)
        report.results.append(cfg_result)
        report.add(check_from_result("Local DNS Configuration", cfg_result, details={"servers": servers}))

        targets = [(n, ip, "direct") for n, ip in self.resolvers.items()]
        targets += [(f"Configured {ip}", ip, "configured") for ip in servers[:MAX_CONFIGURED_SERVERS]
                    if ip not in self.resolvers.values()]
        per_resolver: dict[str, dict[str, list[str]]] = {}
        all_results: list[TestResult] = []

        with ThreadPoolExecutor(max_workers=max(1, min(len(targets) + 1, self.config.max_concurrency)),
                                thread_name_prefix="icpa-dns") as pool:
            futs = [(n, ip, pool.submit(self.probe_server, n, ip, role)) for n, ip, role in targets]
            sys_fut = pool.submit(self.probe_system)
            doh_fut = pool.submit(self.probe_doh) if self.include_doh else None
            for name, ip, fut in futs:
                srv, results, answers = self._safe(fut, name)
                all_results += results
                per_resolver[name] = answers
                report.results.append(srv)
                report.add(check_from_result(
                    f"Resolve via {name} ({ip})", srv,
                    details={"resolver_ip": ip, "answers": answers, "errors": _errors(results)}))
            srv, results, answers = self._safe(sys_fut, SYSTEM_RESOLVER_NAME)
            all_results += results
            per_resolver[SYSTEM_RESOLVER_NAME] = answers
            report.results.append(srv)
            report.add(check_from_result("Resolve via system DNS (OS default)", srv,
                                         details={"answers": answers}))
            if doh_fut is not None:
                srv, results, answers = self._safe(doh_fut, "Cloudflare DoH")
                all_results += results
                per_resolver["Cloudflare DoH"] = answers
                report.results.append(srv)
                report.add(check_from_result("Resolve via DNS-over-HTTPS (Cloudflare)", srv,
                                             details={"answers": answers, "errors": _errors(results)}))

        report.results += all_results
        comparison = self._compare_answers(per_resolver)
        self._flag_outliers(all_results, comparison.result.metrics.get("outlier_resolvers", {}))
        report.add(comparison)
        report.finish()
        return report

    @staticmethod
    def _safe(fut, name: str):  # noqa: ANN001, ANN205
        try:
            return fut.result()
        except Exception as exc:  # noqa: BLE001 - a resolver must not break the module
            log.exception("DNS probe of %s crashed", name)
            err = TestResult(f"dns.server.{name}", "dns_server", status=_S.ERROR, error_type=type(exc).__name__,
                             error_message=str(exc)[:200], summary=f"{name}: could not be tested (internal error).")
            return err, [], {}

    @staticmethod
    def _flag_outliers(results: list[TestResult], outliers: dict[str, list[str]]) -> None:
        for r in results:
            if r.category == "dns_resolution" and r.metadata.get("resolver") in outliers.get(
                    r.metadata.get("domain", ""), []):
                r.metadata["outlier"] = True

    # ---- layer 5: comparison --------------------------------------------------------------
    def _compare_answers(self, per_resolver_answers: dict[str, dict[str, list[str]]]) -> CheckResult:
        """
        Compares the IPs returned by different resolvers for the same domain.
        CDNs legitimately return different IPs, so a mere difference proves nothing. Suspicious
        is a resolver whose answers share nothing with ANY other resolver while the others agree,
        and any public name that resolves to a private/loopback (block page style) address.
        """
        hint_domains: list[str] = []
        outliers: dict[str, list[str]] = {}
        for domain in self.domains:
            answered = {n: set(a.get(domain, [])) for n, a in per_resolver_answers.items() if a.get(domain)}
            if any(is_suspicious_answer(ip) for ips in answered.values() for ip in ips):
                hint_domains.append(domain)
            if len(answered) < 3:
                continue
            for name, ips in answered.items():
                others = [o for n, o in answered.items() if n != name]
                if all(ips.isdisjoint(o) for o in others) and any(
                        not a.isdisjoint(b) for i, a in enumerate(others) for b in others[i + 1:]):
                    outliers.setdefault(domain, []).append(name)

        suspicious = sorted(outliers)
        details = {"no_overlap_domains": suspicious, "outlier_resolvers": outliers,
                   "hijack_hint_domains": hint_domains}
        res = TestResult("dns.comparison", "dns_comparison", protocol="DNS",
                         metrics={"outlier_resolvers": outliers, "hijack_hint_domains": hint_domains})
        if hint_domains:
            res.status, res.interpretation, res.confidence = _S.BLOCKED, "POSSIBLE_DNS_INTERFERENCE", 0.7
            msg = ("Resolver(s) returned a known block-page style address for: " + ", ".join(hint_domains) + ".")
            res.add_evidence(msg)
        elif suspicious:
            res.status, res.severity = _S.PARTIAL, Severity.WARNING
            res.interpretation, res.confidence = "POSSIBLE_DNS_INTERFERENCE", 0.45
            msg = ("One resolver returned answers sharing nothing with any other resolver for: "
                   + "; ".join(f"{d} ({', '.join(outliers[d])})" for d in suspicious)
                   + ". This can indicate DNS interference, but can also be normal CDN/anycast behaviour.")
            res.add_evidence(msg, )
        else:
            res.status = _S.SUCCESS
            msg = "No resolver stands out: answers are consistent across resolvers."
        res.summary = msg
        return check_from_result("DNS Answer Comparison", res, details=details)


def _errors(results: list[TestResult]) -> list[str]:
    return [f"{r.target}: {(r.error_code or r.status.value).lower()}" for r in results
            if not r.ok and not r.skipped]
