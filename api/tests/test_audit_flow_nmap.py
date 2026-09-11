from secaudit_core.audit_flow_nmap import (
    AUDITFLOW_PORT_SPEC,
    NMAP_AUDITFLOW_DISCOVERY,
    NMAP_AUDITFLOW_IDENTITY,
    NMAP_AUDITFLOW_OS,
    NMAP_AUDITFLOW_PORTS,
    NMAP_AUDITFLOW_SERVICE,
    has_management_port,
    host_from_open_ports,
    merge_auditflow_hosts,
    needs_os_fingerprint,
    parse_nmap_gnmap_hosts,
    parse_nmap_service_xml,
)
from secaudit_core.inventory_scan import parse_nmap_discovery_xml


def test_parse_nmap_gnmap_hosts_streams_up_hosts():
    text = """
# Nmap 7.94 scan initiated
Host: 10.0.0.5 (gw.local) Status: Up
Host: 10.0.0.5 (gw.local) Ports: 22/open/tcp//ssh///
Host: 10.0.0.8 () Status: Up
# Nmap done
"""
    hosts = parse_nmap_gnmap_hosts(text)
    assert hosts == [("10.0.0.5", "gw.local"), ("10.0.0.8", None)]

XML = """
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="10.0.0.5" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.9p1" extrainfo="Ubuntu Linux; protocol 2.0" ostype="Linux"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


def test_parse_service_xml_does_not_treat_http_as_network():
    by_ip = parse_nmap_service_xml(XML)
    assert "10.0.0.5" in by_ip
    assert by_ip["10.0.0.5"]["open_ports"] == [22, 80]
    assert by_ip["10.0.0.5"]["services"][0]["product"] == "OpenSSH"
    assert by_ip["10.0.0.5"]["services"][0]["ostype"] == "Linux"
    assert by_ip["10.0.0.5"]["services"][0]["version"] == "8.9p1"


def test_auditflow_ports_include_app_and_network_services():
    ports = {int(p) for p in AUDITFLOW_PORT_SPEC.split(",")}
    assert {22, 23, 80, 139, 443, 445, 5432, 830, 3389, 5985, 8291, 27017}.issubset(ports)


def test_discovery_uses_icmp_and_filtered_tcp_ping():
    assert "-sn" in NMAP_AUDITFLOW_DISCOVERY
    assert "-PE" in NMAP_AUDITFLOW_DISCOVERY
    assert any(token.startswith("-PS") for token in NMAP_AUDITFLOW_DISCOVERY)
    assert "--disable-arp-ping" not in NMAP_AUDITFLOW_DISCOVERY
    assert "--max-rtt-timeout" in NMAP_AUDITFLOW_DISCOVERY
    assert "-sT" in NMAP_AUDITFLOW_IDENTITY
    assert "-sV" in NMAP_AUDITFLOW_IDENTITY
    assert "-O" in NMAP_AUDITFLOW_IDENTITY
    assert "--host-timeout" in NMAP_AUDITFLOW_IDENTITY
    assert "-F" in NMAP_AUDITFLOW_PORTS


def test_discovery_xml_skips_tcp_reset_false_positives():
    xml = """
<nmaprun>
  <host>
    <status state="up" reason="reset"/>
    <address addr="192.168.1.50" addrtype="ipv4"/>
  </host>
  <host>
    <status state="up" reason="echo-reply"/>
    <address addr="192.168.1.145" addrtype="ipv4"/>
  </host>
  <host>
    <status state="up" reason="syn-ack"/>
    <address addr="192.168.1.223" addrtype="ipv4"/>
  </host>
</nmaprun>
"""
    assert parse_nmap_discovery_xml(xml) == [
        {"ip": "192.168.1.50", "hostname": None},
        {"ip": "192.168.1.145", "hostname": None},
        {"ip": "192.168.1.223", "hostname": None},
    ]
    assert parse_nmap_discovery_xml(xml, skip_unreliable=True) == [
        {"ip": "192.168.1.145", "hostname": None},
        {"ip": "192.168.1.223", "hostname": None},
    ]


def test_identity_scan_uses_connect_version_and_os():
    assert "-sT" in NMAP_AUDITFLOW_IDENTITY
    assert "-sV" in NMAP_AUDITFLOW_IDENTITY
    assert "smb-os-discovery,rdp-ntlm-info" in NMAP_AUDITFLOW_IDENTITY
    assert "-sS" not in NMAP_AUDITFLOW_IDENTITY
    assert "-O" in NMAP_AUDITFLOW_OS
    assert "-O" not in NMAP_AUDITFLOW_SERVICE


def test_host_from_open_ports_marks_ssh_as_linux():
    host = host_from_open_ports("192.168.1.145", None, [22, 80])
    assert host["os_guess"] == "Linux"
    assert host["open_ports"] == [22, 80]


def test_management_ports_skip_printers_and_need_os_when_generic():
    assert has_management_port([22, 80])
    assert not has_management_port([80, 443])
    host = parse_nmap_service_xml(XML)["10.0.0.5"]
    assert needs_os_fingerprint(host) is False
    host["os_guess"] = "Linux or Unix"
    assert needs_os_fingerprint(host) is True


OS_XML = """
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="10.0.0.9" addrtype="ipv4"/>
    <address addr="00:11:22:33:44:55" addrtype="mac" vendor="Cisco"/>
    <hostnames>
      <hostname name="edge.local" type="PTR"/>
    </hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="Cisco SSH" ostype="Cisco IOS"/>
      </port>
    </ports>
    <os>
      <osmatch name="Cisco IOS 15.2" accuracy="92">
        <osclass type="router" vendor="Cisco" osfamily="IOS" osgen="15.X" accuracy="92"/>
      </osmatch>
    </os>
  </host>
</nmaprun>
"""


SMB_XML = """
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="10.0.0.20" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="445">
        <state state="open"/>
        <service name="microsoft-ds"/>
        <script id="smb-os-discovery" output="OS: Windows 10 Pro 19045">
          <elem key="os">Windows 10 Pro 19045</elem>
          <elem key="computer_name">DESKTOP-FINANCE</elem>
          <elem key="fqdn">DESKTOP-FINANCE.corp.local</elem>
        </script>
      </port>
    </ports>
  </host>
</nmaprun>
"""


def test_parse_os_match_and_mac_vendor():
    host = parse_nmap_service_xml(OS_XML)["10.0.0.9"]
    assert host["hostname"] == "edge.local"
    assert host["mac_vendor"] == "Cisco"
    assert host["os_guess"] == "Cisco IOS 15.2"
    assert host["os_accuracy"] == 92
    assert host["device_type"] == "router"


def test_parse_smb_os_discovery_hostname_and_os():
    host = parse_nmap_service_xml(SMB_XML)["10.0.0.20"]
    assert host["os_guess"] == "Windows 10 Pro 19045"
    assert host["hostname"] == "DESKTOP-FINANCE.corp.local"


def test_banner_beats_generic_linux_osmatch():
    generic = parse_nmap_service_xml(XML)["10.0.0.5"]
    generic["os_guess"] = "Linux 4.15"
    generic["os_accuracy"] = 90
    merged = merge_auditflow_hosts(generic, None)
    assert merged is not None
    assert "Ubuntu" in (merged["os_guess"] or "")


def test_parse_service_xml_guesses_os_from_ssh_banner():
    host = parse_nmap_service_xml(XML)["10.0.0.5"]
    assert host["os_guess"] == "Ubuntu Linux"


NAGIOS_XML = """
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="192.0.2.248" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.9p1" ostype="Linux"/>
      </port>
      <port protocol="tcp" portid="8000">
        <state state="open"/>
        <service name="nagios-nsca" product="Nagios NSCA"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

OPENWRT_XML = """
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="OpenWrt uHTTPd" ostype="Linux"/>
      </port>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="Dropbear sshd" ostype="Linux"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


def test_nagios_service_is_not_used_as_os():
    host = parse_nmap_service_xml(NAGIOS_XML)["192.0.2.248"]
    assert "nagios" not in (host["os_guess"] or "").lower()
    assert host["os_guess"] == "Linux"


def test_openwrt_http_banner_is_openwrt_not_uhttpd_product():
    host = parse_nmap_service_xml(OPENWRT_XML)["192.168.1.1"]
    assert host["os_guess"] == "OpenWrt"
    assert "uhttpd" not in (host["os_guess"] or "").lower()
