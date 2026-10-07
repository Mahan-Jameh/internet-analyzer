"""
testconfig.py
=============
Centralized timeouts, retry policy, concurrency and target groups.

Modules receive a :class:`NetworkTestConfig` instead of reading scattered
constants, so a timeout is changed in exactly one place and tests can inject
tiny values.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app import constants as C


@dataclass(frozen=True)
class RetryPolicy:
    max_retries: int = 1             # extra attempts after the first
    backoff_seconds: float = 0.25
    # Only these outcomes are worth retrying: they can be transient.
    # A refusal, NXDOMAIN or certificate error is deterministic - retrying wastes time.
    retry_on_codes: frozenset[str] = frozenset({
        "TIMEOUT", "WOULD_BLOCK", "NO_RESPONSE", "CONNECTION_RESET", "CONNECTION_ABORTED",
        "DNS_TEMPORARY_FAILURE", "NO_BUFFER_SPACE", "TLS_PROTOCOL_ERROR",
        "TLS_HANDSHAKE_TIMEOUT", "TLS_HANDSHAKE_RESET", "TLS_HANDSHAKE_EOF",
    })


@dataclass(frozen=True)
class TargetGroups:
    """Targets are chosen per purpose; no single IP represents 'the Internet'."""

    connectivity: tuple[tuple[str, str], ...] = (
        ("Cloudflare", "1.1.1.1"), ("Google", "8.8.8.8"), ("Quad9", "9.9.9.9"),
    )
    latency: tuple[tuple[str, str], ...] = tuple(C.LATENCY_TARGETS.items())
    dns_resolvers: tuple[tuple[str, str], ...] = tuple(C.DNS_RESOLVERS.items())
    dns_domains: tuple[str, ...] = tuple(C.DNS_TEST_DOMAINS)
    tls: tuple[str, ...] = tuple(C.TLS_TEST_HOSTS)
    http: tuple[str, ...] = (C.HTTP_TEST_URL_TLS, C.HTTP_TEST_URL_PLAIN)
    # Port scan: empty means "use the default public targets"; users override it.
    port_scan: tuple[str, ...] = ()
    public_ip_services: tuple[tuple[str, str], ...] = (
        ("ipify-v4", C.IPV4_TEST_URL), ("ipify-v6", C.IPV6_TEST_URL),
    )
    ipv4_probe_hosts: tuple[str, ...] = ("1.1.1.1", "8.8.8.8")
    ipv6_probe_hosts: tuple[str, ...] = ("2606:4700:4700::1111", "2001:4860:4860::8888")


@dataclass(frozen=True)
class NetworkTestConfig:
    connect_timeout: float = C.TCP_TIMEOUT
    read_timeout: float = C.HTTP_TIMEOUT
    dns_timeout: float = C.DNS_TIMEOUT
    tls_timeout: float = C.TLS_TIMEOUT
    udp_timeout: float = C.UDP_TIMEOUT
    ping_timeout: float = C.PING_TIMEOUT
    latency_probes: int = 10             # per target; 10 keeps a full run short, raise it for finer jitter data
    max_concurrency: int = 8             # independent modules running at once
    scan_concurrency: int = 16           # parallel probes inside one scan
    retry: RetryPolicy = field(default_factory=RetryPolicy)
    targets: TargetGroups = field(default_factory=TargetGroups)

    def __post_init__(self) -> None:
        if self.max_concurrency < 1:
            raise ValueError("max_concurrency must be >= 1")
        if self.latency_probes < 1:
            raise ValueError("latency_probes must be >= 1")

    @property
    def connect_timeout_ms(self) -> int:
        return int(self.connect_timeout * 1000)


DEFAULT_CONFIG = NetworkTestConfig()
