from secaudit_core.audit_flow_match import (
    decide_profile,
    fingerprint_from_facts,
    merge_extra_profiles,
    pretty_fingerprint,
    rank_application_profiles,
    rank_profiles,
    review_skip_without_auth,
)

PROFILES = [
    {
        "id": 1,
        "profile_name": "Ubuntu 24",
        "os_name": "Ubuntu Linux",
        "os_version": "24.04",
        "os_vendor": "Canonical Ltd.",
        "platform": "linux",
        "category_slug": "linux-platform",
    },
    {
        "id": 2,
        "profile_name": "AlmaLinux 9",
        "os_name": "AlmaLinux",
        "os_version": "9",
        "os_vendor": "AlmaLinux",
        "platform": "linux",
        "category_slug": "linux-platform",
    },
    {
        "id": 3,
        "profile_name": "Microsoft Windows Server 2019 Standard",
        "os_name": "Microsoft Windows Server 2019 Standard",
        "os_version": "10.0.17763",
        "os_vendor": "Microsoft",
        "platform": "windows",
        "category_slug": "windows-platform",
    },
    {
        "id": 4,
        "profile_name": "Cisco IOS 15",
        "os_name": "cisco",
        "os_version": "15",
        "os_vendor": "cisco",
        "platform": "network",
        "category_slug": "network-platform",
    },
    {
        "id": 5,
        "profile_name": "Ubuntu 22",
        "os_name": "Ubuntu Linux",
        "os_version": "22.04",
        "os_vendor": "Canonical Ltd.",
        "platform": "linux",
        "category_slug": "linux-platform",
    },
    {
        "id": 6,
        "profile_name": "Red Hat Enterprise Linux (RHEL) 9",
        "os_name": "Red Hat Enterprise Linux",
        "os_version": "9.0",
        "os_vendor": "Red Hat, Inc.",
        "platform": "linux",
        "category_slug": "linux-platform",
    },
    {
        "id": 7,
        "profile_name": "RedOS 7",
        "os_name": "RedOS Linux",
        "os_version": "7",
        "os_vendor": "RedOS",
        "platform": "linux",
        "category_slug": "linux-platform",
    },
    {
        "id": 8,
        "profile_name": "Astra Linux Special Edition 1.7 (Smolensk)",
        "os_name": "Astra Linux Special Edition (Smolensk)",
        "os_version": "1.7",
        "os_vendor": "RusBitech-Astra",
        "platform": "linux",
        "category_slug": "linux-platform",
    },
    {
        "id": 9,
        "profile_name": "Astra Linux Community Edition 2.12 (Orel)",
        "os_name": "Astra Linux Community Edition (Orel)",
        "os_version": "2.12",
        "os_vendor": "RusBitech-Astra",
        "platform": "linux",
        "category_slug": "linux-platform",
    },
    {
        "id": 10,
        "profile_name": "Microsoft Windows 11 Enterprise for workstations",
        "os_name": "Windows 11",
        "os_version": "22H2",
        "os_vendor": "Microsoft",
        "platform": "windows",
        "category_slug": "windows-platform",
    },
    {
        "id": 11,
        "profile_name": "PCI DSS v4.0.1: Linux system components checks",
        "os_name": "Linux",
        "os_version": "*",
        "os_vendor": "*",
        "platform": "linux",
        "category_slug": "linux-platform",
    },
    {
        "id": 12,
        "profile_name": "Nginx",
        "os_name": None,
        "os_version": None,
        "os_vendor": None,
        "platform": "linux",
        "category_slug": "services",
    },
    {
        "id": 13,
        "profile_name": "Eltex ESR",
        "os_name": "Eltex ESR",
        "os_version": None,
        "os_vendor": "Eltex",
        "platform": "network",
        "category_slug": "network-platform",
    },
    {
        "id": 14,
        "profile_name": "Eltex MES",
        "os_name": "Eltex MES",
        "os_version": None,
        "os_vendor": "Eltex",
        "platform": "network",
        "category_slug": "network-platform",
    },
    {
        "id": 15,
        "profile_name": "MikroTik RouterOS",
        "os_name": "MikroTik RouterOS",
        "os_version": "7",
        "os_vendor": "MikroTik",
        "platform": "network",
        "category_slug": "network-platform",
    },
    {
        "id": 16,
        "profile_name": "Xiaomi MiWiFi",
        "os_name": "XiaoQiang",
        "os_version": None,
        "os_vendor": "Xiaomi",
        "platform": "network",
        "category_slug": "network-platform",
    },
    {
        "id": 17,
        "profile_name": "PostgreSQL",
        "os_name": None,
        "os_version": None,
        "os_vendor": None,
        "platform": "linux",
        "category_slug": "services",
    },
]


def test_ubuntu_24_ranks_first():
    fp = fingerprint_from_facts(
        platform="linux",
        os_release='PRETTY_NAME="Ubuntu 24.04.1 LTS"\nID=ubuntu\nVERSION_ID="24.04"',
    )
    ranked = rank_profiles(fp, PROFILES)
    assert ranked[0]["profile_id"] == 1
    assert ranked[0]["confidence"] >= 70
    assert {item["profile_id"] for item in ranked} == {1}


def test_alma_9_ranks_first():
    fp = fingerprint_from_facts(
        platform="linux",
        os_release='PRETTY_NAME="AlmaLinux 9.4"\nID=almalinux\nVERSION_ID="9.4"',
    )
    ranked = rank_profiles(fp, PROFILES)
    assert ranked[0]["profile_id"] == 2


def test_windows_2019_ranks_first():
    fp = fingerprint_from_facts(platform="windows", win_caption="Microsoft Windows Server 2019 Datacenter")
    ranked = rank_profiles(fp, PROFILES)
    assert ranked[0]["profile_id"] == 3


def test_cisco_ranks_network():
    fp = fingerprint_from_facts(platform=None, nmap_os="Cisco IOS 15.2", services="22/ssh Cisco IOS")
    assert fp["platform"] == "network"
    ranked = rank_profiles(fp, PROFILES)
    assert ranked[0]["profile_id"] == 4


def test_unknown_host_has_no_match():
    fp = fingerprint_from_facts(platform=None, services="80/http nginx", open_ports=[80])
    ranked = rank_profiles(fp, PROFILES)
    assert ranked == []


def test_rhel_id_does_not_match_ubuntu_or_alma():
    fp = fingerprint_from_facts(
        platform="linux",
        os_release='PRETTY_NAME="Red Hat Enterprise Linux 9.4 (Plow)"\nID=rhel\nVERSION_ID="9.4"\nID_LIKE="fedora"',
    )
    ranked = rank_profiles(fp, PROFILES)
    assert ranked[0]["profile_id"] == 6
    assert {item["profile_id"] for item in ranked} == {6}


def test_redos_matches_redos_not_rhel():
    fp = fingerprint_from_facts(
        platform="linux",
        os_release='PRETTY_NAME="RED OS 7.3"\nID=redos\nVERSION_ID="7.3"',
    )
    ranked = rank_profiles(fp, PROFILES)
    assert ranked[0]["profile_id"] == 7


def test_astra_se_prefers_smolensk_over_orel():
    fp = fingerprint_from_facts(
        platform="linux",
        os_release=(
            'PRETTY_NAME="Astra Linux Special Edition 1.7.5 (Smolensk)"\n'
            "ID=astra\nVERSION_ID=\"1.7\""
        ),
    )
    ranked = rank_profiles(fp, PROFILES)
    assert ranked[0]["profile_id"] == 8
    assert 9 not in {item["profile_id"] for item in ranked}


def test_ubuntu_22_is_not_selected_for_ubuntu_24():
    fp = fingerprint_from_facts(
        platform="linux",
        os_release='PRETTY_NAME="Ubuntu 22.04.4 LTS"\nID=ubuntu\nVERSION_ID="22.04"',
    )
    ranked = rank_profiles(fp, PROFILES)
    assert ranked[0]["profile_id"] == 5
    assert 1 not in {item["profile_id"] for item in ranked}


def test_windows_11_is_not_server_2019():
    fp = fingerprint_from_facts(
        platform="windows",
        win_caption="Microsoft Windows 11 Enterprise\nVersion=10.0.22621\nProductType=1\nBuildNumber=22621",
    )
    ranked = rank_profiles(fp, PROFILES)
    assert ranked[0]["profile_id"] == 10
    assert 3 not in {item["profile_id"] for item in ranked}


def test_windows_10_is_not_matched_as_server_2019():
    fp = fingerprint_from_facts(
        platform="windows",
        win_caption="Microsoft Windows 10 Pro\nVersion=10.0.19045\nProductType=1\nBuildNumber=19045",
    )
    ranked = rank_profiles(fp, PROFILES)
    assert ranked == []


def test_generic_and_service_profiles_are_not_ranked():
    fp = fingerprint_from_facts(
        platform="linux",
        os_release='PRETTY_NAME="Ubuntu 24.04.1 LTS"\nID=ubuntu\nVERSION_ID="24.04"',
    )
    ranked = rank_profiles(fp, PROFILES)
    ids = {item["profile_id"] for item in ranked}
    assert 11 not in ids
    assert 12 not in ids


def test_port_only_ssh_does_not_pick_a_distro():
    fp = fingerprint_from_facts(platform=None, services="22/ssh OpenSSH", open_ports=[22])
    assert fp["platform"] == "linux"
    assert not fp.get("family") or fp.get("family") not in {"ubuntu", "rhel", "alma"}
    ranked = rank_profiles(fp, PROFILES)
    assert ranked == []


def test_authenticated_ubuntu_is_auto_selected():
    fp = fingerprint_from_facts(
        platform="linux",
        os_release='PRETTY_NAME="Ubuntu 24.04.1 LTS"\nID=ubuntu\nVERSION_ID="24.04"',
    )
    decision = decide_profile(fp, PROFILES, authenticated=True)
    assert decision["auto_select"] is True
    assert decision["profile_id"] == 1
    assert decision["skip_reason"] is None


def test_nmap_only_match_needs_confirmation():
    fp = fingerprint_from_facts(
        platform=None,
        nmap_os=None,
        services="22/ssh OpenSSH Ubuntu Linux",
        open_ports=[22],
    )
    assert fp["source"] == "nmap"
    decision = decide_profile(fp, PROFILES, authenticated=True)
    assert decision["profile_id"] in {1, 5}
    assert decision["auto_select"] is False
    assert decision["skip_reason"] == "low_confidence"


def test_pretty_fingerprint_uses_os_release_name():
    fp = fingerprint_from_facts(
        platform="linux",
        os_release='PRETTY_NAME="Ubuntu 24.04.1 LTS"\nID=ubuntu\nVERSION_ID="24.04"',
    )
    assert pretty_fingerprint(fp) == "Ubuntu 24.04.1 LTS"


def test_pretty_fingerprint_ignores_nmap_service_noise():
    fp = fingerprint_from_facts(
        platform="linux",
        os_release='PRETTY_NAME="openSUSE Leap 16.0"\nID="opensuse-leap"\nVERSION_ID="16.0"',
        services="8000/nagios-nsca Nagios NSCA\n22/ssh OpenSSH",
    )
    assert pretty_fingerprint(fp) == "openSUSE Leap 16.0"
    assert fp["family"] == "opensuse"


def test_pretty_fingerprint_does_not_use_service_banner_as_os():
    fp = fingerprint_from_facts(
        platform=None,
        nmap_os=None,
        services="8000/nagios-nsca Nagios NSCA\n22/ssh OpenSSH",
        open_ports=[22, 8000],
    )
    assert "nagios" not in (pretty_fingerprint(fp) or "").lower()
    assert pretty_fingerprint(fp) == "Linux"


def test_hostnamectl_operating_system_is_pretty_name():
    fp = fingerprint_from_facts(
        platform="linux",
        os_release="Static hostname: leap16\nOperating System: openSUSE Leap 16.0\nKernel: Linux 6.12.0",
    )
    assert pretty_fingerprint(fp) == "openSUSE Leap 16.0"


def test_fingerprint_strips_bracketed_paste_noise():
    fp = fingerprint_from_facts(
        platform="linux",
        os_release='\x1b[?2004l\nPRETTY_NAME="Ubuntu 22.04.4 LTS"\nID=ubuntu\nVERSION_ID="22.04"',
    )
    assert pretty_fingerprint(fp) == "Ubuntu 22.04.4 LTS"
    assert "[?2004" not in (fp.get("pretty") or "")
    assert "[?2004" not in (fp.get("raw") or "")


def test_eltex_esr_is_not_mes():
    fp = fingerprint_from_facts(
        platform="network",
        os_release="Eltex ESR-1000 Software, Version 1.23.0",
    )
    ranked = rank_profiles(fp, PROFILES)
    assert ranked[0]["profile_id"] == 13
    assert 14 not in {item["profile_id"] for item in ranked if item["confidence"] >= ranked[0]["confidence"]}
    decision = decide_profile(fp, PROFILES, authenticated=True)
    assert decision["profile_id"] == 13
    assert decision["auto_select"] is True


def test_eltex_mes_is_not_esr():
    fp = fingerprint_from_facts(
        platform="network",
        os_release="Eltex MES-3324 Software Version 4.0.18",
    )
    ranked = rank_profiles(fp, PROFILES)
    assert ranked[0]["profile_id"] == 14
    decision = decide_profile(fp, PROFILES, authenticated=True)
    assert decision["profile_id"] == 14
    assert decision["auto_select"] is True


def test_mikrotik_banner_matches_routeros():
    fp = fingerprint_from_facts(platform=None, os_release="RouterOS 7.15\nMikroTik")
    assert fp["family"] == "mikrotik"
    assert fp["platform"] == "network"
    ranked = rank_profiles(fp, PROFILES)
    assert ranked[0]["profile_id"] == 15


def test_xiaomi_xiaoqiang_banner():
    fp = fingerprint_from_facts(
        platform=None,
        os_release="DISTRIB_ID='XiaoQiang'\nDISTRIB_RELEASE='1.0.26'\n",
    )
    assert fp["family"] == "xiaomi"
    assert fp["platform"] == "network"
    ranked = rank_profiles(fp, PROFILES)
    assert ranked[0]["profile_id"] == 16


def test_application_profiles_prefer_nmap_product():
    apps = rank_application_profiles(
        services="80/http nginx\n443/http nginx",
        open_ports=[80, 443],
        profiles=PROFILES,
    )
    assert apps[0]["profile_id"] == 12
    assert apps[0]["confidence"] >= 80


def test_application_profiles_port_only_are_weaker():
    apps = rank_application_profiles(
        services="80/http\n5432/tcp",
        open_ports=[80, 5432],
        profiles=PROFILES,
    )
    by_id = {item["profile_id"]: item for item in apps}
    assert by_id[12]["confidence"] == 62
    assert by_id[17]["confidence"] == 62


def test_merge_extra_profiles_keeps_operator_selection():
    suggested = [
        {"profile_id": 12, "profile_name": "Nginx", "confidence": 90},
        {"profile_id": 17, "profile_name": "PostgreSQL", "confidence": 62},
    ]
    merged = merge_extra_profiles(
        [{"profile_id": 12, "profile_name": "Nginx", "confidence": 90, "selected": False}],
        suggested,
    )
    by_id = {item["profile_id"]: item for item in merged}
    assert by_id[12]["selected"] is False
    assert by_id[17]["selected"] is False
    auto = merge_extra_profiles(None, suggested)
    assert auto[0]["selected"] is True
    assert auto[1]["selected"] is False


def test_review_skip_marks_profiled_hosts_available():
    reason, detail = review_skip_without_auth(
        probe_skip="unreachable",
        has_profile=True,
        discovered=True,
    )
    assert reason is None
    assert detail is None


def test_review_skip_uses_no_profile_when_host_is_live():
    reason, _detail = review_skip_without_auth(
        probe_skip="unreachable",
        has_profile=False,
        discovered=True,
    )
    assert reason == "no_matching_profile"


def test_review_skip_keeps_auth_failed():
    reason, _detail = review_skip_without_auth(
        probe_skip="auth_failed",
        has_profile=True,
        discovered=True,
    )
    assert reason == "auth_failed"
