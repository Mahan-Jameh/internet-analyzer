"""
constants.py
============
All fixed, non-user-configurable values live here so that no module
contains "magic numbers" or hard-coded strings scattered around the code.
"""

from __future__ import annotations

APP_NAME = "Internet Connectivity & Protocol Analyzer"
APP_VERSION = "2.0.1"
ORG_NAME = "ICPA"

# --------------------------------------------------------------------------
# Timeouts (seconds)
# --------------------------------------------------------------------------
DEFAULT_SOCKET_TIMEOUT = 3.0
DNS_TIMEOUT = 3.0
TCP_TIMEOUT = 2.5
UDP_TIMEOUT = 2.5
TLS_TIMEOUT = 4.0
HTTP_TIMEOUT = 6.0
PING_TIMEOUT = 2.0
TRACEROUTE_TIMEOUT = 20.0

# --------------------------------------------------------------------------
# Well known public resolvers used for DNS comparison / poisoning checks
# --------------------------------------------------------------------------
DNS_RESOLVERS = {
    "Google": "8.8.8.8",
    "Cloudflare": "1.1.1.1",
    "Quad9": "9.9.9.9",
    "OpenDNS": "208.67.222.222",
}

# Domains that are extremely unlikely to be geo/CDN inconsistent, used to
# compare answers returned by different resolvers.
DNS_TEST_DOMAINS = [
    "cloudflare.com",
    "google.com",
    "wikipedia.org",
]

# --------------------------------------------------------------------------
# TCP ports allowed to be scanned (well known / common service & tunnel ports)
# Scanning is intentionally restricted to this fixed allow-list.
# --------------------------------------------------------------------------
ALLOWED_TCP_PORTS = [
    22, 25, 53, 80, 81, 110, 143, 443, 444, 445,
    465, 587, 993, 995, 2052, 2053, 2082, 2083, 2086, 2087,
    2095, 2096, 3389, 8080, 8443,
]

PORT_SERVICE_NAMES = {
    22: "SSH", 25: "SMTP", 53: "DNS", 80: "HTTP", 81: "HTTP-Alt",
    110: "POP3", 143: "IMAP", 443: "HTTPS", 444: "SNPP", 445: "SMB",
    465: "SMTPS", 587: "SMTP-Submission", 993: "IMAPS", 995: "POP3S",
    2052: "CF-HTTP", 2053: "CF-HTTPS", 2082: "CF-HTTP", 2083: "CF-HTTPS",
    2086: "cPanel", 2087: "WHM", 2095: "Webmail", 2096: "Webmail-SSL",
    3389: "RDP", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
}

# Hosts used as generic TCP scan targets (Cloudflare + Google anycast IPs,
# always reachable under normal conditions).
TCP_SCAN_TARGETS = {
    "Cloudflare": "1.1.1.1",
    "Google": "8.8.8.8",
}

# --------------------------------------------------------------------------
# UDP ports of interest
# --------------------------------------------------------------------------
ALLOWED_UDP_PORTS = [53, 123, 443, 500, 4500, 51820]

UDP_PORT_NAMES = {
    53: "DNS",
    123: "NTP",
    443: "QUIC/HTTP3",
    500: "IKE/IPsec",
    4500: "IPsec NAT-T",
    51820: "WireGuard",
}

# --------------------------------------------------------------------------
# VPN transport probing (connectivity only, never claims a VPN "works")
# --------------------------------------------------------------------------
VPN_TCP_PORTS = [443, 8443, 2053, 2087]
VPN_UDP_PORTS = [443, 51820, 500, 4500]

# --------------------------------------------------------------------------
# Latency test targets
# --------------------------------------------------------------------------
LATENCY_TARGETS = {
    "Cloudflare": "1.1.1.1",
    "Google": "8.8.8.8",
    "Quad9": "9.9.9.9",
}
LATENCY_PING_COUNT = 4

# --------------------------------------------------------------------------
# MTU test
# --------------------------------------------------------------------------
MTU_TEST_HOST = "1.1.1.1"
MTU_MIN = 1200
MTU_MAX = 1500
MTU_ETHERNET_OVERHEAD = 28  # 20 byte IP header + 8 byte ICMP header

# --------------------------------------------------------------------------
# HTTP test targets
# --------------------------------------------------------------------------
HTTP_TEST_URL_PLAIN = "http://neverssl.com"
HTTP_TEST_URL_TLS = "https://www.cloudflare.com"
HTTP2_TEST_URL = "https://www.cloudflare.com"
HTTP3_TEST_HOST = "cloudflare-quic.com"
REDIRECT_TEST_URL = "http://cloudflare.com"

# --------------------------------------------------------------------------
# TLS test targets
# --------------------------------------------------------------------------
TLS_TEST_HOSTS = ["www.cloudflare.com", "www.google.com"]
TLS_TEST_PORT = 443

# SNI filtering probe: the same server IP is contacted with different SNI
# names. A TLS handshake that is reset/dropped only for some names points to
# filtering based on the SNI field rather than on the IP address.
SNI_PROBE_BASELINE_HOST = "www.cloudflare.com"
SNI_PROBE_NAMES = ["www.cloudflare.com", "example.com", "www.wikipedia.org", "www.google.com"]

# --------------------------------------------------------------------------
# TCP stall ("16-20 KB") test. Some filtering systems let a connection start
# normally and then cut or freeze it after roughly 14-34 KB were transferred.
# A download of known size from a CDN endpoint made for such tests reveals it.
# --------------------------------------------------------------------------
TCP_STALL_URL_TEMPLATE = "https://speed.cloudflare.com/__down?bytes={size}"
TCP_STALL_SMALL_BYTES = 1024
TCP_STALL_TEST_BYTES = 131072
TCP_STALL_SUSPECT_RANGE = (10_000, 40_000)
TCP_STALL_TIMEOUT = 6.0

# --------------------------------------------------------------------------
# Website reachability (layered DNS -> TCP -> TLS -> HTTP check per site).
# CONTROL sites should work on any healthy connection; TEST sites are widely
# used services people commonly ask about. Users can replace the test list.
# --------------------------------------------------------------------------
SITE_CONTROL_HOSTS = ["www.cloudflare.com", "www.wikipedia.org"]
SITE_DEFAULT_TEST_HOSTS = [
    "www.google.com", "www.youtube.com", "www.instagram.com",
    "telegram.org", "www.whatsapp.com", "x.com",
]
SITE_MAX_CUSTOM_HOSTS = 20
SITE_CHECK_TIMEOUT = 5.0
SITE_HTTP_BLOCK_STATUS = 451

# --------------------------------------------------------------------------
# Proxy / VPN detection. If a proxy or tunnel is active, every test measures
# the tunnel instead of the user's real connection, so this is checked first.
# --------------------------------------------------------------------------
LOCAL_PROXY_PORTS = {
    1080: "SOCKS proxy (common default)",
    2080: "proxy client (common default)",
    7890: "Clash/Mihomo HTTP proxy (common default)",
    7891: "Clash/Mihomo SOCKS proxy (common default)",
    8086: "Oblivion/warp-plus proxy (documented default)",
    8087: "Oblivion PAC server (documented default)",
    10808: "v2ray/xray SOCKS (common default)",
    10809: "v2ray/xray HTTP (common default)",
    50051: "Oblivion TUN-mode gRPC (documented default)",
}
LOCAL_PORT_TIMEOUT = 0.3
VPN_ADAPTER_HINTS = (
    "wintun", "tap-windows", "wireguard", "warp", "openvpn", "nordlynx",
    "amnezia", "outline", "hiddify", "v2ray", "xray", "mihomo", "clash",
    "vpn", "tunnel", "tun0", "utun",
)
PROXY_ENV_VARS = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy")

# --------------------------------------------------------------------------
# Protocol whitelist probe (opt-in). Research on Iran's protocol filter
# (Bock et al., FOCI 2020) found that only DNS/HTTP/HTTPS were allowed on
# ports 53/80/443 and that only the first data packets were inspected.
# --------------------------------------------------------------------------
PROTOCOL_PROBE_HOST = "www.cloudflare.com"
PROTOCOL_PROBE_MONITORED_PORT = 443
PROTOCOL_PROBE_CONTROL_PORT = 8443
PROTOCOL_PROBE_TIMEOUT = 5.0
PROTOCOL_PROBE_PAYLOAD = b"ICPA diagnostic probe - this is not a real protocol.\r\n"

# --------------------------------------------------------------------------
# DoH / DoT
# --------------------------------------------------------------------------
DOH_ENDPOINTS = {
    "Cloudflare": "https://cloudflare-dns.com/dns-query",
    "Google": "https://dns.google/dns-query",
}
DOT_SERVERS = {
    "Cloudflare": "1.1.1.1",
    "Quad9": "9.9.9.9",
}
DOT_PORT = 853

# --------------------------------------------------------------------------
# WebSocket echo test
# --------------------------------------------------------------------------
WEBSOCKET_TEST_URL = "wss://echo.websocket.org"

# --------------------------------------------------------------------------
# IP address info service (public IP / ISP / geo)
# --------------------------------------------------------------------------
IP_INFO_URL = "https://ipapi.co/json/"
IP_INFO_URL_FALLBACK = "https://ip-api.com/json/"
IPV6_TEST_URL = "https://api64.ipify.org?format=json"
IPV4_TEST_URL = "https://api.ipify.org?format=json"

# --------------------------------------------------------------------------
# Status levels used everywhere for color coding
# --------------------------------------------------------------------------
STATUS_OK = "OK"
STATUS_WARNING = "WARNING"
STATUS_FAILED = "FAILED"
STATUS_UNKNOWN = "UNKNOWN"

STATUS_COLORS = {
    STATUS_OK: "#2ecc71",
    STATUS_WARNING: "#f1c40f",
    STATUS_FAILED: "#e74c3c",
    STATUS_UNKNOWN: "#95a5a6",
}

# --------------------------------------------------------------------------
# Misc
# --------------------------------------------------------------------------
MAX_THREAD_WORKERS = 20
LOG_DIR_NAME = "logs"
REPORTS_DIR_NAME = "reports"
PROFILES_DIR_NAME = "profiles"
HISTORY_DIR_NAME = "history"
HISTORY_MAX_FILES = 100
REPEAT_MAX_COUNT = 20
REPEAT_MAX_INTERVAL_SECONDS = 3600
CONFIG_FILE_NAME = "config.json"
