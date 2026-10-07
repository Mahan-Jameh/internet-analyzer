"""
dns_test.py
===========
Queries several well known public DNS resolvers directly (bypassing the
OS resolver) using dnspython, then compares the answers to look for
inconsistencies that can indicate DNS poisoning / DNS-based blocking,
as well as plain timeouts.

Note: this module only ever *observes and reports* differences. It never
declares with certainty that poisoning is happening - see analyzer.py
for how these observations are turned into probabilistic language.
"""

from __future__ import annotations

import ipaddress
import socket
import time

import dns.exception
import dns.resolver
import httpx

from app.constants import DNS_RESOLVERS, DNS_TEST_DOMAINS, DNS_TIMEOUT, DOH_ENDPOINTS
from app.logger import get_logger
from app.models import CheckResult, ModuleReport, Status
from app.utils.helpers import resolve_host

log = get_logger(__name__)

SYSTEM_RESOLVER_NAME = "System"


def is_suspicious_answer(ip: str) -> bool:
    """
    True if ``ip`` is an address that a public domain should never resolve
    to: private (RFC 1918), loopback, unspecified or link-local. Filtering
    systems often answer blocked names with such addresses (block pages).
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_private or addr.is_loopback or addr.is_unspecified or addr.is_link_local


class DNSTester:
    def __init__(self) -> None:
        pass

    def run_all(self) -> ModuleReport:
        report = ModuleReport(module_name="DNS Test")

        per_resolver_answers: dict[str, dict[str, list[str]]] = {}

        for resolver_name, resolver_ip in DNS_RESOLVERS.items():
            check, answers = self._resolve_with_server(resolver_name, resolver_ip)
            report.add(check)
            per_resolver_answers[resolver_name] = answers

        # The resolver the machine actually uses is the one most likely to be
        # tampered with, so it is compared against the public resolvers too.
        system_check, system_answers = self._resolve_with_system()
        report.add(system_check)
        per_resolver_answers[SYSTEM_RESOLVER_NAME] = system_answers

        # Encrypted DNS travels over HTTPS and cannot be rewritten in transit
        # by plain-DNS tampering, which makes it a useful reference answer.
        doh_check, doh_answers = self._resolve_with_doh()
        report.add(doh_check)
        per_resolver_answers["Cloudflare DoH"] = doh_answers

        report.add(self._compare_answers(per_resolver_answers))
        report.finish()
        return report

    # ------------------------------------------------------------------ #
    def _resolve_with_doh(self) -> tuple[CheckResult, dict[str, list[str]]]:
        endpoint = DOH_ENDPOINTS["Cloudflare"]
        name = "Resolve via DNS-over-HTTPS (Cloudflare)"
        answers: dict[str, list[str]] = {}
        errors: list[str] = []
        start = time.perf_counter()

        for domain in DNS_TEST_DOMAINS:
            try:
                response = httpx.get(
                    endpoint,
                    params={"name": domain, "type": "A"},
                    headers={"accept": "application/dns-json"},
                    timeout=DNS_TIMEOUT + 2,
                )
                payload = response.json()
                answers[domain] = sorted(
                    str(a["data"]) for a in payload.get("Answer", []) if a.get("type") == 1
                )
            except (httpx.HTTPError, ValueError, KeyError, TypeError) as exc:
                answers[domain] = []
                errors.append(f"{domain}: {exc.__class__.__name__}")

        duration_ms = (time.perf_counter() - start) * 1000.0
        resolved = sum(1 for v in answers.values() if v)
        details = {"answers": answers, "errors": errors}

        if resolved == 0:
            return CheckResult(
                name=name, status=Status.WARNING,
                message="DNS-over-HTTPS could not be used, so it is not part of the comparison.",
                details=details, duration_ms=duration_ms), answers
        status = Status.OK if resolved == len(DNS_TEST_DOMAINS) else Status.WARNING
        return CheckResult(
            name=name, status=status,
            message=f"{resolved}/{len(DNS_TEST_DOMAINS)} domains resolved over HTTPS in {duration_ms:.0f} ms.",
            details=details, duration_ms=duration_ms), answers

    # ------------------------------------------------------------------ #
    def _resolve_with_system(self) -> tuple[CheckResult, dict[str, list[str]]]:
        answers: dict[str, list[str]] = {}
        start = time.perf_counter()
        for domain in DNS_TEST_DOMAINS:
            answers[domain] = resolve_host(domain, family=socket.AF_INET, timeout=DNS_TIMEOUT)
        duration_ms = (time.perf_counter() - start) * 1000.0
        resolved = sum(1 for v in answers.values() if v)
        details = {"answers": answers}
        name = "Resolve via system DNS (OS default)"

        if resolved == 0:
            status = Status.FAILED
            message = "The system DNS could not resolve any test domain."
        elif resolved < len(DNS_TEST_DOMAINS):
            status = Status.WARNING
            message = f"Only {resolved}/{len(DNS_TEST_DOMAINS)} domains resolved by the system DNS."
        else:
            status = Status.OK
            message = f"All {len(DNS_TEST_DOMAINS)} test domains resolved in {duration_ms:.0f} ms."
        return CheckResult(name=name, status=status, message=message, details=details,
                           duration_ms=duration_ms), answers

    # ------------------------------------------------------------------ #
    def _resolve_with_server(self, resolver_name: str, resolver_ip: str) -> tuple[CheckResult, dict[str, list[str]]]:
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = [resolver_ip]
        resolver.timeout = DNS_TIMEOUT
        resolver.lifetime = DNS_TIMEOUT

        answers: dict[str, list[str]] = {}
        errors: list[str] = []
        start = time.perf_counter()

        for domain in DNS_TEST_DOMAINS:
            try:
                response = resolver.resolve(domain, "A")
                answers[domain] = sorted(str(r) for r in response)
            except dns.resolver.NXDOMAIN:
                answers[domain] = []
                errors.append(f"{domain}: NXDOMAIN")
            except dns.exception.Timeout:
                answers[domain] = []
                errors.append(f"{domain}: timeout")
            except dns.exception.DNSException as exc:
                answers[domain] = []
                errors.append(f"{domain}: {exc.__class__.__name__}")

        duration_ms = (time.perf_counter() - start) * 1000.0
        resolved_count = sum(1 for v in answers.values() if v)

        details = {"resolver_ip": resolver_ip, "answers": answers, "errors": errors}

        if resolved_count == 0:
            return (
                CheckResult(
                    name=f"Resolve via {resolver_name} ({resolver_ip})",
                    status=Status.FAILED,
                    message="No domain could be resolved - resolver unreachable or blocked.",
                    details=details,
                    duration_ms=duration_ms,
                ),
                answers,
            )
        if resolved_count < len(DNS_TEST_DOMAINS):
            return (
                CheckResult(
                    name=f"Resolve via {resolver_name} ({resolver_ip})",
                    status=Status.WARNING,
                    message=f"Only {resolved_count}/{len(DNS_TEST_DOMAINS)} domains resolved.",
                    details=details,
                    duration_ms=duration_ms,
                ),
                answers,
            )
        return (
            CheckResult(
                name=f"Resolve via {resolver_name} ({resolver_ip})",
                status=Status.OK,
                message=f"All {len(DNS_TEST_DOMAINS)} test domains resolved in {duration_ms:.0f} ms.",
                details=details,
                duration_ms=duration_ms,
            ),
            answers,
        )

    # ------------------------------------------------------------------ #
    def _compare_answers(self, per_resolver_answers: dict[str, dict[str, list[str]]]) -> CheckResult:
        """
        Compares the IPs returned by different resolvers for the same domain.
        Complete disagreement (no overlap at all) between independent public
        resolvers for a well known domain is a classic DNS poisoning symptom.
        """
        suspicious_domains: list[str] = []
        suspicious_hint_domains: list[str] = []

        outliers: dict[str, list[str]] = {}

        for domain in DNS_TEST_DOMAINS:
            answered = {
                name: set(answers.get(domain, []))
                for name, answers in per_resolver_answers.items()
                if answers.get(domain)
            }

            # A public domain resolving to a private/loopback address is a
            # block-page style answer, even if only one resolver returned it.
            if any(is_suspicious_answer(ip) for ips in answered.values() for ip in ips):
                suspicious_hint_domains.append(domain)

            if len(answered) < 3:
                continue  # too few answers to tell an outlier from CDN variance

            # CDNs legitimately return different IPs to different resolvers,
            # so a mere difference proves nothing. What is suspicious is a
            # resolver whose answers share nothing with ANY other resolver
            # while the rest of the resolvers do agree with each other.
            for name, ips in answered.items():
                others = [o for n, o in answered.items() if n != name]
                disjoint_from_all = all(ips.isdisjoint(o) for o in others)
                rest_agree = any(
                    not a.isdisjoint(b)
                    for i, a in enumerate(others)
                    for b in others[i + 1:]
                )
                if disjoint_from_all and rest_agree:
                    outliers.setdefault(domain, []).append(name)

        suspicious_domains = sorted(outliers)

        details = {
            "no_overlap_domains": suspicious_domains,
            "outlier_resolvers": outliers,
            "hijack_hint_domains": suspicious_hint_domains,
        }

        if suspicious_hint_domains:
            return CheckResult(
                name="DNS Answer Comparison",
                status=Status.FAILED,
                message=(
                    f"Resolver(s) returned a known block-page style address for: "
                    f"{', '.join(suspicious_hint_domains)}."
                ),
                details=details,
            )
        if suspicious_domains:
            return CheckResult(
                name="DNS Answer Comparison",
                status=Status.WARNING,
                message=(
                    "One resolver returned answers sharing nothing with any other resolver for: "
                    + "; ".join(f"{d} ({', '.join(outliers[d])})" for d in suspicious_domains)
                    + ". This can indicate DNS interference, but can also be normal "
                    "CDN/anycast behaviour."
                ),
                details=details,
            )
        return CheckResult(
            name="DNS Answer Comparison",
            status=Status.OK,
            message="No resolver stands out: answers are consistent across resolvers.",
            details=details,
        )
