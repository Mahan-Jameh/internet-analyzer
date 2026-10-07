from app.diag import localnet as L

ROUTE4 = """
IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0      192.168.1.1    192.168.1.50     25
          0.0.0.0          0.0.0.0         On-link       10.8.0.2      5
        127.0.0.0        255.0.0.0         On-link         127.0.0.1    331
"""
ROUTE6 = """
IPv6 Route Table
Active Routes:
 If Metric Network Destination      Gateway
 12    281 ::/0                     fe80::1
  1    331 ::1/128                  On-link
"""
IPCONFIG = """
Windows IP Configuration

Wireless LAN adapter Wi-Fi:

   Connection-specific DNS Suffix  . :
   IPv4 Address. . . . . . . . . . . : 192.168.1.50(Preferred)
   Default Gateway . . . . . . . . . : 192.168.1.1
   DNS Servers . . . . . . . . . . . : 5.200.200.200
                                       8.8.8.8

Ethernet adapter Ethernet 2:
   IPv4 Address. . . . . . . . . . . : 10.0.0.9
"""


def test_route_print_is_parsed_language_independently():
    v4 = L.parse_route_print_v4(ROUTE4)
    assert [(e.gateway, e.interface, e.metric) for e in v4] == [("192.168.1.1", "192.168.1.50", 25), (None, "10.8.0.2", 5)]
    v6 = L.parse_route_print_v6(ROUTE6)
    assert v6[0].gateway == "fe80::1" and v6[0].metric == 281


def test_no_default_route_gives_empty_list():
    assert L.parse_route_print_v4("nothing here") == [] and L.parse_route_print_v6("") == []


def test_unix_route_parsing():
    out = "default via 192.168.1.1 dev eth0 proto dhcp metric 100\n"
    e = L.parse_ip_route(out, "IPv4")[0]
    assert (e.gateway, e.interface, e.metric) == ("192.168.1.1", "eth0", 100)


def test_dns_and_adapter_parsing():
    assert L.parse_ipconfig_dns(IPCONFIG) == ["5.200.200.200", "8.8.8.8"]
    assert L.parse_powershell_dns('[{"ServerAddresses":["1.1.1.1","x"]}]') == ["1.1.1.1"]
    assert L.parse_powershell_dns("garbage") == []
    assert L.adapter_name_for_ip(IPCONFIG, "192.168.1.50") == "Wi-Fi"
    assert L.adapter_name_for_ip(IPCONFIG, "10.0.0.9") == "Ethernet 2"
    assert L.adapter_name_for_ip(IPCONFIG, "1.2.3.4") is None


def test_source_address_usability(monkeypatch):
    assert L.SourceAddress("IPv6", "fe80::1").usable is False
    assert L.SourceAddress("IPv4", "192.168.1.5").usable is True
    assert L.SourceAddress("IPv4", None).usable is False
