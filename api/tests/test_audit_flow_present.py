import base64
from types import SimpleNamespace

import pytest

from secaudit_core.audit_flow_present import host_to_read, reprobe_target_ids, run_to_read
from secaudit_core.ssh_fingerprint import verify_or_pin_host_key


def _key_b64(payload: bytes) -> str:
    inner = b"\x00\x00\x00\x0bssh-ed25519" + payload
    return base64.b64encode(inner).decode()


def test_verify_or_pin_host_key_tofu():
    key_b64 = _key_b64(b"a" * 32)
    fingerprint, entry = verify_or_pin_host_key(
        hostname="10.0.0.5",
        key_type="ssh-ed25519",
        key_b64=key_b64,
    )
    assert fingerprint.startswith("SHA256:")
    assert entry.startswith("10.0.0.5 ssh-ed25519 ")
    again, _ = verify_or_pin_host_key(
        hostname="10.0.0.5",
        key_type="ssh-ed25519",
        key_b64=key_b64,
        expected_fingerprint=fingerprint,
    )
    assert again == fingerprint


def test_verify_or_pin_host_key_rejects_mismatch():
    expected, _ = verify_or_pin_host_key(
        hostname="10.0.0.5",
        key_type="ssh-ed25519",
        key_b64=_key_b64(b"a" * 32),
    )
    with pytest.raises(ValueError, match="host key mismatch"):
        verify_or_pin_host_key(
            hostname="10.0.0.5",
            key_type="ssh-ed25519",
            key_b64=_key_b64(b"b" * 32),
            expected_fingerprint=expected,
        )


def test_reprobe_target_ids_auth_failed_and_explicit():
    failed = SimpleNamespace(id=1, job_run_id=None, skip_reason="auth_failed", credential_id=None)
    ok = SimpleNamespace(id=2, job_run_id=None, skip_reason=None, credential_id=8)
    launched = SimpleNamespace(id=3, job_run_id=99, skip_reason=None, credential_id=8)
    checking = SimpleNamespace(id=4, job_run_id=None, skip_reason="checking", credential_id=1)
    run = SimpleNamespace(hosts=[failed, ok, launched, checking])
    assert reprobe_target_ids(run) == [1, 4]
    assert reprobe_target_ids(run, host_ids=[2, 3]) == [2]


def test_host_to_read_includes_scores_and_inventory_reuse():
    row = SimpleNamespace(
        id=1,
        ip_address="10.0.0.1",
        hostname="gw.local",
        platform="linux",
        os_guess="Ubuntu 24.04.1 LTS",
        open_ports="22,80",
        credential_id=1,
        credential=SimpleNamespace(label="root"),
        profile_id=1,
        profile_name="Ubuntu 24",
        confidence=90,
        alternatives_json=[],
        extra_profiles_json=[{"profile_id": 12, "profile_name": "Nginx", "selected": True, "confidence": 90}],
        extra_runs_json=[{"profile_id": 12, "profile_name": "Nginx", "job_run_id": 99}],
        selected=True,
        skip_reason=None,
        skip_detail=None,
        job_run_id=50,
        ephemeral_host_id=7,
        ssh_host_key_fingerprint="SHA256:abc",
    )
    payload = host_to_read(
        row,
        summaries={
            50: {
                "job_run_id": 50,
                "total_checks": 10,
                "passed": 8,
                "failed": 2,
                "compliance_percent": 80.0,
                "job_status": "completed",
            },
            99: {
                "job_run_id": 99,
                "total_checks": 5,
                "passed": 5,
                "failed": 0,
                "compliance_percent": 100.0,
                "job_status": "completed",
            },
        },
        reused_host_ids={7},
    )
    assert payload["inventory_reused"] is True
    assert payload["ephemeral_host_id"] == 7
    assert payload["check_summary"]["compliance_percent"] == 80.0
    assert payload["extra_checks"][0]["job_run_id"] == 99
    assert payload["extra_checks"][0]["profile_id"] == 12
    assert payload["extra_checks"][0]["passed"] == 5


def test_host_to_read_strips_terminal_noise_from_os_guess():
    row = SimpleNamespace(
        id=1,
        ip_address="192.0.2.248",
        hostname=None,
        platform="linux",
        os_guess="\x1b[?2004l",
        open_ports="22",
        credential_id=None,
        credential=None,
        profile_id=None,
        profile_name=None,
        confidence=0,
        alternatives_json=[],
        extra_profiles_json=[],
        extra_runs_json=[],
        selected=False,
        skip_reason="no_matching_profile",
        skip_detail=None,
        job_run_id=None,
        ephemeral_host_id=None,
        ssh_host_key_fingerprint=None,
    )
    assert host_to_read(row)["os_guess"] is None


def test_run_to_read_keeps_hosts_ordered_by_id():
    def host_row(host_id: int, ip: str):
        return SimpleNamespace(
            id=host_id,
            ip_address=ip,
            hostname=None,
            platform=None,
            os_guess=None,
            open_ports=None,
            credential_id=None,
            credential=None,
            profile_id=None,
            profile_name=None,
            confidence=0,
            alternatives_json=[],
            extra_profiles_json=[],
            extra_runs_json=[],
            selected=False,
            skip_reason=None,
            skip_detail=None,
            job_run_id=None,
            ephemeral_host_id=None,
            ssh_host_key_fingerprint=None,
        )

    run = SimpleNamespace(
        id=7,
        status="ready",
        targets_json=["192.168.1.0/24"],
        error_message=None,
        hosts_found=3,
        save_to_inventory=False,
        started_at=None,
        finished_at=None,
        created_at=None,
        hosts=[
            host_row(12, "192.168.1.201"),
            host_row(10, "192.168.1.1"),
            host_row(11, "192.168.1.188"),
        ],
        credentials=[],
    )
    payload = run_to_read(run)
    assert [item["id"] for item in payload["hosts"]] == [10, 11, 12]
    assert [item["ip_address"] for item in payload["hosts"]] == [
        "192.168.1.1",
        "192.168.1.188",
        "192.168.1.201",
    ]

