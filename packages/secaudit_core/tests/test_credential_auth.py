"""Tests for SSH key passphrase helpers."""

from secaudit_core.credential_auth import ssh_auth_from_credential
from secaudit_core.enums import CredentialType


class _Cred:
    credential_type = CredentialType.SSH_KEY
    encrypted_key_passphrase = None


def test_ssh_auth_from_credential_returns_key_without_passphrase():
    password, private_key, key_passphrase = ssh_auth_from_credential(
        _Cred(),
        "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----",
    )
    assert password is None
    assert private_key.startswith("-----BEGIN OPENSSH")
    assert key_passphrase is None


def test_ssh_auth_from_credential_returns_password_for_ssh_password():
    cred = _Cred()
    cred.credential_type = CredentialType.SSH_PASSWORD
    password, private_key, key_passphrase = ssh_auth_from_credential(cred, "secret")
    assert password == "secret"
    assert private_key is None
    assert key_passphrase is None
