import pytest

from secaudit_core.inventory_scan import expand_scan_target, parse_nmap_discovery_xml, parse_nmap_port_scan_xml

SAMPLE_XML = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sn 192.168.1.10" start="1">
  <host>
    <status state="up" reason="echo-reply"/>
    <address addr="192.168.1.10" addrtype="ipv4"/>
    <hostnames>
      <hostname name="host.local" type="PTR"/>
    </hostnames>
  </host>
  <runstats><finished time="1"/><hosts up="1" down="0" total="1"/></runstats>
</nmaprun>
"""


def test_parse_nmap_discovery_xml_basic():
    hosts = parse_nmap_discovery_xml(SAMPLE_XML)
    assert hosts == [{"ip": "192.168.1.10", "hostname": "host.local"}]


def test_parse_nmap_discovery_xml_strips_noise():
    noisy = f"WARNING: something\n{SAMPLE_XML}\nextra trailing text"
    hosts = parse_nmap_discovery_xml(noisy)
    assert hosts[0]["ip"] == "192.168.1.10"


def test_parse_nmap_discovery_xml_rejects_empty():
    with pytest.raises(ValueError, match="empty XML"):
        parse_nmap_discovery_xml("   ")


def test_parse_nmap_port_scan_xml_open_ports():
    xml = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="10.0.0.5" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22"><state state="open"/></port>
      <port protocol="tcp" portid="80"><state state="closed"/></port>
    </ports>
  </host>
</nmaprun>
"""
    by_ip = parse_nmap_port_scan_xml(xml)
    assert by_ip["10.0.0.5"]["open_ports"] == [22]


def test_parse_nmap_discovery_xml_can_skip_tcp_reset():
    xml = """<nmaprun>
  <host>
    <status state="up" reason="reset"/>
    <address addr="192.168.1.50" addrtype="ipv4"/>
  </host>
  <host>
    <status state="up" reason="echo-reply"/>
    <address addr="192.168.1.145" addrtype="ipv4"/>
  </host>
</nmaprun>"""
    assert [h["ip"] for h in parse_nmap_discovery_xml(xml)] == ["192.168.1.50", "192.168.1.145"]
    assert [h["ip"] for h in parse_nmap_discovery_xml(xml, skip_unreliable=True)] == ["192.168.1.145"]


def test_parse_nmap_discovery_xml_keeps_syn_ack():
    xml = """<nmaprun>
  <host>
    <status state="up" reason="reset"/>
    <address addr="192.168.1.50" addrtype="ipv4"/>
  </host>
  <host>
    <status state="up" reason="syn-ack"/>
    <address addr="192.168.1.223" addrtype="ipv4"/>
  </host>
</nmaprun>"""
    assert [h["ip"] for h in parse_nmap_discovery_xml(xml, skip_unreliable=True)] == ["192.168.1.223"]


def test_expand_scan_target_cidr_includes_slow_lan_hosts():
    hosts = expand_scan_target("192.168.1.0/24")
    assert hosts is not None
    assert "192.168.1.223" in hosts
    assert "192.168.1.0" not in hosts
    assert "192.168.1.255" not in hosts
    assert expand_scan_target("192.168.1.223") == ["192.168.1.223"]
    assert expand_scan_target("lab.example") is None
