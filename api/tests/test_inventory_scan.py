import pytest

from app.services.inventory_scan import validate_nmap_flags, validate_scan_target


def test_validate_scan_target_accepts_ip():
    assert validate_scan_target("192.168.1.10") == "192.168.1.10"


def test_validate_scan_target_accepts_cidr():
    assert validate_scan_target("10.0.0.0/24") == "10.0.0.0/24"


def test_validate_scan_target_rejects_oversized_cidr():
    with pytest.raises(ValueError, match="Network too large"):
        validate_scan_target("10.0.0.0/8")


def test_validate_scan_target_rejects_empty():
    with pytest.raises(ValueError, match="1–256"):
        validate_scan_target("   ")


def test_validate_scan_target_accepts_hostname():
    assert validate_scan_target("host.example.com") == "host.example.com"


def test_validate_nmap_flags_accepts_safe_flags():
    assert validate_nmap_flags("-sn -F") == ["-sn", "-F"]


def test_validate_nmap_flags_rejects_script_injection():
    with pytest.raises(ValueError, match="not allowed"):
        validate_nmap_flags("--script vuln")


def test_validate_nmap_flags_rejects_shell_metacharacters():
    with pytest.raises(ValueError, match="invalid characters"):
        validate_nmap_flags("-sn; rm -rf /")
