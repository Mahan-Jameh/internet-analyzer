from app.utils.helpers import parse_ping_rtts, validate_target_host

WINDOWS_EN = """
Pinging 1.1.1.1 with 32 bytes of data:
Reply from 1.1.1.1: bytes=32 time=12ms TTL=57
Reply from 1.1.1.1: bytes=32 time<1ms TTL=57
Request timed out.
Reply from 1.1.1.1: bytes=32 time=14ms TTL=57

Ping statistics for 1.1.1.1:
    Packets: Sent = 4, Received = 3, Lost = 1 (25% loss),
Approximate round trip times in milli-seconds:
    Minimum = 0ms, Maximum = 14ms, Average = 8ms
"""

# German Windows translates the word "time" ("Zeit") but keeps TTL and ms.
WINDOWS_DE = """
Antwort von 1.1.1.1: Bytes=32 Zeit=12ms TTL=57
Antwort von 1.1.1.1: Bytes=32 Zeit=13ms TTL=57
Minimum = 12ms, Maximum = 13ms, Mittelwert = 12ms
"""

LINUX = """
64 bytes from 1.1.1.1: icmp_seq=1 ttl=57 time=12.3 ms
64 bytes from 1.1.1.1: icmp_seq=2 ttl=57 time=13.1 ms
rtt min/avg/max/mdev = 12.300/12.700/13.100/0.400 ms
"""

UNREACHABLE = """
Reply from 192.168.1.1: Destination host unreachable.
Packet needs to be fragmented but DF set.
Reply from 10.0.0.1: TTL expired in transit.
"""


def test_windows_english_ignores_summary_line():
    assert parse_ping_rtts(WINDOWS_EN) == [12.0, 0.5, 14.0]


def test_localized_windows_output_still_parsed():
    assert parse_ping_rtts(WINDOWS_DE) == [12.0, 13.0]


def test_linux_output():
    assert parse_ping_rtts(LINUX) == [12.3, 13.1]


def test_error_replies_are_not_counted_as_success():
    assert parse_ping_rtts(UNREACHABLE) == []


def test_validate_target_host_accepts_hosts_and_ips():
    assert validate_target_host("example.com") == "example.com"
    assert validate_target_host(" 1.1.1.1 ") == "1.1.1.1"
    assert validate_target_host("2606:4700:4700::1111") == "2606:4700:4700::1111"


def test_validate_target_host_rejects_option_injection_and_junk():
    for bad in ("-f", "--help", "a b", "exa mple.com", "", None, "a;b", "$(x).com"):
        assert validate_target_host(bad) is None
