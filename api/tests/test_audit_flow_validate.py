import pytest

from app.models import CredentialType
from app.schemas import AuditFlowCreate
from app.services.audit_flow import validate_credentials, validate_targets


def test_validate_targets_multiple_cidr():
    assert validate_targets(["10.0.0.0/24", "192.168.1.10"]) == ["10.0.0.0/24", "192.168.1.10"]


def test_validate_targets_splits_spaces_and_commas():
    assert validate_targets(["192.168.1.0/24 192.168.2.0/24, 10.0.0.1; 172.16.0.0/24"]) == [
        "192.168.1.0/24",
        "192.168.2.0/24",
        "10.0.0.1",
        "172.16.0.0/24",
    ]


def test_validate_targets_rejects_empty():
    with pytest.raises(ValueError, match="At least one"):
        validate_targets([])


def test_validate_credentials_allows_empty():
    assert validate_credentials([]) == []


def test_validate_credentials_requires_secret():
    with pytest.raises(ValueError, match="username and secret"):
        validate_credentials([{"credential_type": "ssh_password", "username": "root", "secret": ""}])


def test_validate_credentials_accepts_pairs():
    cleaned = validate_credentials(
        [
            {"credential_type": CredentialType.SSH_PASSWORD, "username": "root", "secret": "x"},
            {"credential_type": "winrm", "username": "Administrator", "secret": "y", "label": "win"},
        ]
    )
    assert len(cleaned) == 2
    assert cleaned[1]["label"] == "win"


def test_validate_credentials_strips_copied_newlines():
    cleaned = validate_credentials(
        [{"credential_type": "ssh_password", "username": " root ", "secret": "secret\r\n"}]
    )
    assert cleaned[0]["username"] == "root"
    assert cleaned[0]["secret"] == "secret"


def test_validate_credentials_preserves_ssh_key_passphrase():
    cleaned = validate_credentials(
        [
            {
                "credential_type": "ssh_key",
                "username": "root",
                "secret": "-----BEGIN KEY-----\nabc\n-----END KEY-----",
                "key_passphrase": "  phrase  ",
            }
        ]
    )
    assert cleaned[0]["key_passphrase"] == "phrase"


def test_audit_flow_create_allows_empty_credentials():
    data = AuditFlowCreate(targets=["192.168.1.0/24"], credentials=[])
    assert data.credentials == []
