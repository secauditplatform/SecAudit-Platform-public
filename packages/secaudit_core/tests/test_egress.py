"""Tests for outbound URL / header SSRF guards."""

from __future__ import annotations

import ipaddress

import pytest

from secaudit_core.egress import (
    sanitize_outbound_headers,
    validate_channel_config_egress,
    validate_public_https_url,
    validate_smtp_endpoint,
)


def test_validate_public_https_url_accepts_example(monkeypatch):
    monkeypatch.setattr(
        "secaudit_core.egress._resolve_host_ips",
        lambda _host: [ipaddress.ip_address("93.184.216.34")],
    )
    assert validate_public_https_url("https://example.com/hook") == "https://example.com/hook"


def test_validate_public_https_url_rejects_http(monkeypatch):
    with pytest.raises(ValueError, match="scheme"):
        validate_public_https_url("http://example.com/hook")


def test_validate_public_https_url_rejects_localhost():
    with pytest.raises(ValueError, match="not allowed"):
        validate_public_https_url("https://localhost/hook", resolve_dns=False)


def test_validate_public_https_url_rejects_metadata_ip():
    with pytest.raises(ValueError, match="blocked"):
        validate_public_https_url("https://169.254.169.254/latest", resolve_dns=False)


def test_validate_public_https_url_rejects_private_resolution(monkeypatch):
    monkeypatch.setattr(
        "secaudit_core.egress._resolve_host_ips",
        lambda _host: [ipaddress.ip_address("10.0.0.5")],
    )
    with pytest.raises(ValueError, match="blocked"):
        validate_public_https_url("https://evil.example/hook")


def test_sanitize_outbound_headers_strips_host():
    cleaned = sanitize_outbound_headers(
        {"Authorization": "Bearer x", "Host": "evil", "X-Api-Key": "k"}
    )
    assert cleaned == {"Authorization": "Bearer x", "X-Api-Key": "k"}


def test_validate_channel_config_egress_sanitizes_headers(monkeypatch):
    monkeypatch.setattr(
        "secaudit_core.egress._resolve_host_ips",
        lambda _host: [ipaddress.ip_address("1.2.3.4")],
    )
    config = validate_channel_config_egress(
        channel_type="webhook",
        config_json={
            "webhook_url": "https://hooks.example/x",
            "headers": {"Authorization": "t", "Transfer-Encoding": "chunked"},
        },
    )
    assert config is not None
    assert config["headers"] == {"Authorization": "t"}


def test_validate_smtp_endpoint_rejects_private(monkeypatch):
    monkeypatch.setattr(
        "secaudit_core.egress._resolve_host_ips",
        lambda _host: [ipaddress.ip_address("10.0.0.8")],
    )
    with pytest.raises(ValueError, match="blocked|not allowed"):
        validate_smtp_endpoint("smtp.example.com", 587)


def test_validate_smtp_endpoint_allows_private_when_opted_in(monkeypatch):
    monkeypatch.setattr(
        "secaudit_core.egress._resolve_host_ips",
        lambda _host: [ipaddress.ip_address("10.0.0.8")],
    )
    host, port = validate_smtp_endpoint("mailpit", 1025, allow_private=True)
    assert host == "mailpit"
    assert port == 1025


def test_validate_channel_config_egress_validates_smtp(monkeypatch):
    monkeypatch.setattr(
        "secaudit_core.egress._resolve_host_ips",
        lambda _host: [ipaddress.ip_address("1.2.3.4")],
    )
    config = validate_channel_config_egress(
        channel_type="email",
        config_json={"smtp_host": "smtp.example.com", "smtp_port": 587},
    )
    assert config["smtp_host"] == "smtp.example.com"
    assert config["smtp_port"] == 587
