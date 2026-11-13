"""Sync pre-flight probe against a host + credential (runs on the worker)."""

from __future__ import annotations

import time
from typing import Any

from secaudit_core.credential_auth import ssh_auth_from_credential
from secaudit_core.enums import CredentialType
from secaudit_core.preflight import host_platform, tcp_reachable
from secaudit_core.secrets import decrypt_secret
from secaudit_core.settings import SecAuditSettings


def _check(name: str, status: str, detail: str | None = None) -> dict[str, Any]:
    return {"name": name, "status": status, "detail": detail}


def _ssh_exec(client, command: str, timeout: int = 8) -> tuple[int, str]:
    stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
    try:
        stdin.close()
    except Exception:
        pass
    out = (stdout.read() or b"").decode("utf-8", errors="replace").strip()
    err = (stderr.read() or b"").decode("utf-8", errors="replace").strip()
    code = stdout.channel.recv_exit_status()
    text = out or err
    return code, text


def _probe_ssh_stack(
    *,
    hostname: str,
    port: int,
    username: str,
    password: str | None,
    private_key: str | None,
    key_passphrase: str | None,
    known_hosts_entry: str | None,
    check_extras: bool,
) -> list[dict[str, Any]]:
    import paramiko

    checks: list[dict[str, Any]] = []
    _ = known_hosts_entry  # probe accepts any host key; inventory pinning is separate
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        kwargs: dict[str, Any] = {
            "hostname": hostname,
            "port": port,
            "username": username,
            "timeout": 10,
            "auth_timeout": 10,
            "banner_timeout": 10,
            "allow_agent": False,
            "look_for_keys": False,
        }
        if private_key:
            from io import StringIO

            pkey = None
            for loader in (
                paramiko.Ed25519Key,
                paramiko.ECDSAKey,
                paramiko.RSAKey,
            ):
                try:
                    pkey = loader.from_private_key(StringIO(private_key), password=key_passphrase)
                    break
                except Exception:
                    continue
            if pkey is None:
                checks.append(_check("auth", "fail", "invalid_private_key"))
                return checks
            kwargs["pkey"] = pkey
        else:
            kwargs["password"] = password or ""
        client.connect(**kwargs)
        checks.append(_check("auth", "ok", "ssh"))
    except paramiko.AuthenticationException:
        checks.append(_check("auth", "fail", "auth_failed"))
        return checks
    except Exception as exc:
        checks.append(_check("auth", "fail", str(exc)[:240] or "ssh_error"))
        return checks

    if not check_extras:
        client.close()
        return checks

    try:
        code, text = _ssh_exec(client, "sudo -n true")
        if code == 0:
            checks.append(_check("sudo", "ok", "passwordless_sudo"))
        else:
            checks.append(_check("sudo", "fail", (text or "sudo_requires_password")[:240]))
    except Exception as exc:
        checks.append(_check("sudo", "fail", str(exc)[:240]))

    try:
        code, text = _ssh_exec(client, "command -v python3 || command -v python")
        if code == 0 and text:
            checks.append(_check("python3", "ok", text.splitlines()[0][:120]))
        else:
            checks.append(_check("python3", "fail", "not_found"))
    except Exception as exc:
        checks.append(_check("python3", "fail", str(exc)[:240]))

    try:
        code, text = _ssh_exec(client, "command -v oscap")
        if code == 0 and text:
            checks.append(_check("oscap", "ok", text.splitlines()[0][:120]))
        else:
            checks.append(_check("oscap", "skip", "not_found"))
    except Exception as exc:
        checks.append(_check("oscap", "skip", str(exc)[:240]))

    try:
        client.close()
    except Exception:
        pass
    return checks


def _probe_winrm(*, hostname: str, port: int, username: str, password: str) -> list[dict[str, Any]]:
    import winrm

    checks: list[dict[str, Any]] = []
    host = hostname if ":" not in hostname else f"[{hostname}]"
    endpoints = []
    if port in (5986, 443):
        endpoints.append(f"https://{host}:{port or 5986}/wsman")
    endpoints.append(f"http://{host}:{port if port not in (5986, 443) else 5985}/wsman")
    last_error = "auth_failed"
    for endpoint in endpoints:
        try:
            session = winrm.Session(
                endpoint,
                auth=(username, password),
                transport="ntlm",
                server_cert_validation="ignore",
            )
            result = session.run_ps(
                "$u = [Security.Principal.WindowsIdentity]::GetCurrent(); "
                "$p = New-Object Security.Principal.WindowsPrincipal($u); "
                "Write-Output ('User=' + $u.Name); "
                "Write-Output ('Admin=' + $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))"
            )
            if result.status_code != 0:
                last_error = (result.std_err or b"").decode("utf-8", errors="replace")[:240] or "winrm_error"
                continue
            text = (result.std_out or b"").decode("utf-8", errors="replace").strip()
            checks.append(_check("auth", "ok", "winrm"))
            admin = "admin=true" in text.lower().replace(" ", "")
            checks.append(_check("admin", "ok" if admin else "fail", text.splitlines()[-1][:120] if text else None))
            return checks
        except Exception as exc:
            last_error = str(exc)[:240] or "winrm_error"
            continue
    checks.append(_check("auth", "fail", last_error))
    return checks


def _probe_snmp(*, hostname: str, port: int, cred, settings: SecAuditSettings) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    try:
        from app.snmp_probe import probe_snmp_addresses
    except Exception:
        checks.append(_check("auth", "skip", "snmp_unavailable"))
        return checks
    secret = decrypt_secret(cred.encrypted_secret, settings)
    ctype = cred.credential_type
    if ctype == CredentialType.SNMP_V2C:
        report = probe_snmp_addresses(
            [hostname],
            version="2c",
            port=port or 161,
            community=secret,
        )
    else:
        auth_key = secret
        priv_key = None
        if getattr(cred, "encrypted_key_passphrase", None):
            priv_key = decrypt_secret(cred.encrypted_key_passphrase, settings)
        report = probe_snmp_addresses(
            [hostname],
            version="3",
            port=port or 161,
            username=getattr(cred, "username", None),
            auth_protocol=getattr(cred, "service_username", None),
            auth_key=auth_key,
            priv_protocol=getattr(cred, "snmp_priv_protocol", None),
            priv_key=priv_key,
        )
    if report.hits:
        hit = report.hits[0]
        detail = hit.sys_name or hit.sys_descr or "snmp"
        checks.append(_check("auth", "ok", str(detail)[:120]))
    else:
        checks.append(_check("auth", "fail", "snmp_no_response"))
    return checks


def _probe_netmiko(*, hostname: str, port: int, username: str, password: str) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    try:
        from netmiko import ConnectHandler
    except ImportError:
        checks.append(_check("auth", "skip", "netmiko_unavailable"))
        return checks
    for device_type in ("cisco_ios", "mikrotik_routeros", "juniper_junos", "arista_eos", "huawei"):
        try:
            with ConnectHandler(
                device_type=device_type,
                host=hostname,
                port=port or 22,
                username=username,
                password=password,
                timeout=8,
                conn_timeout=8,
                auth_timeout=8,
                banner_timeout=8,
            ) as connection:
                output = ""
                try:
                    output = connection.send_command("show version", read_timeout=8)
                except Exception:
                    output = ""
                checks.append(_check("auth", "ok", f"netmiko:{device_type}"))
                if output:
                    checks.append(_check("facts", "ok", output.splitlines()[0][:120]))
                return checks
        except Exception:
            continue
    checks.append(_check("auth", "fail", "netmiko_auth_failed"))
    return checks


def run_preflight_probe(
    *,
    hostname: str,
    port: int,
    os_type: str | None,
    credential,
    settings: SecAuditSettings,
    known_hosts_entry: str | None = None,
) -> dict[str, Any]:
    started = time.perf_counter()
    checks: list[dict[str, Any]] = []
    host = (hostname or "").strip()
    platform = host_platform(os_type)
    ctype = credential.credential_type
    if hasattr(ctype, "value"):
        ctype = ctype.value if isinstance(ctype.value, str) else ctype

    # Resolve TCP port by credential / OS defaults.
    tcp_port = int(port or 22)
    if ctype == CredentialType.WINRM or ctype == "winrm":
        tcp_port = int(port or 5985)
    elif ctype in (CredentialType.SNMP_V2C, CredentialType.SNMP_V3, "snmp_v2c", "snmp_v3"):
        tcp_port = int(port or 161)

    is_snmp = ctype in (CredentialType.SNMP_V2C, CredentialType.SNMP_V3, "snmp_v2c", "snmp_v3")
    # Remote VPN/SSH targets often drop the first SYN under Docker NAT; retry.
    ok_tcp, tcp_detail = tcp_reachable(host, tcp_port, timeout=8.0, attempts=2)
    if is_snmp:
        checks.append(_check("tcp", "skip" if not ok_tcp else "ok", "snmp_udp" if not ok_tcp else tcp_detail))
    else:
        checks.append(_check("tcp", "ok" if ok_tcp else "fail", tcp_detail))
        if not ok_tcp:
            return {
                "ok": False,
                "target": f"{host}:{tcp_port}",
                "credential_id": getattr(credential, "id", None),
                "platform": platform,
                "checks": checks,
                "duration_ms": int((time.perf_counter() - started) * 1000),
            }

    secret = decrypt_secret(credential.encrypted_secret, settings)
    if ctype in (CredentialType.SSH_PASSWORD, CredentialType.SSH_KEY, "ssh_password", "ssh_key"):
        password, private_key, key_passphrase = ssh_auth_from_credential(credential, secret, settings)
        extras = platform in {"linux", "unix"}
        checks.extend(
            _probe_ssh_stack(
                hostname=host,
                port=tcp_port,
                username=getattr(credential, "username", None) or "",
                password=password,
                private_key=private_key,
                key_passphrase=key_passphrase,
                known_hosts_entry=known_hosts_entry,
                check_extras=extras,
            )
        )
        if platform == "network" and checks and checks[-1].get("name") == "auth" and checks[-1].get("status") == "fail":
            # Fall back to Netmiko for network appliances after SSH login miss.
            checks.extend(
                _probe_netmiko(
                    hostname=host,
                    port=tcp_port,
                    username=getattr(credential, "username", None) or "",
                    password=secret,
                )
            )
    elif ctype in (CredentialType.WINRM, "winrm"):
        checks.extend(
            _probe_winrm(
                hostname=host,
                port=tcp_port,
                username=getattr(credential, "username", None) or "",
                password=secret,
            )
        )
    elif is_snmp:
        checks.extend(_probe_snmp(hostname=host, port=tcp_port, cred=credential, settings=settings))
    else:
        checks.append(_check("auth", "skip", f"unsupported_type:{ctype}"))

    auth_ok = any(c["name"] == "auth" and c["status"] == "ok" for c in checks)
    hard_fail = any(c["name"] in {"tcp", "auth"} and c["status"] == "fail" for c in checks)
    return {
        "ok": auth_ok and not hard_fail,
        "target": f"{host}:{tcp_port}",
        "credential_id": getattr(credential, "id", None),
        "platform": platform,
        "checks": checks,
        "duration_ms": int((time.perf_counter() - started) * 1000),
    }


def probe_host_record(db, host_id: int, credential_id: int | None, settings: SecAuditSettings) -> dict[str, Any]:
    from sqlalchemy import select
    from sqlalchemy.orm import selectinload

    from secaudit_core.host_credentials import linked_credentials
    from secaudit_core.models import Credential, Host, HostCredentialLink

    host = db.execute(
        select(Host)
        .options(
            selectinload(Host.credential_links).selectinload(HostCredentialLink.credential),
            selectinload(Host.credential),
        )
        .where(Host.id == host_id)
    ).scalar_one_or_none()
    if host is None:
        return {"ok": False, "error": "host_not_found", "checks": [], "duration_ms": 0, "target": ""}

    cred = None
    if credential_id is not None:
        cred = db.get(Credential, credential_id)
        if cred is None:
            return {
                "ok": False,
                "error": "credential_not_found",
                "checks": [],
                "duration_ms": 0,
                "target": host.hostname,
            }
    else:
        linked = linked_credentials(host)
        cred = linked[0] if linked else None
    if cred is None:
        return {
            "ok": False,
            "error": "no_credential",
            "target": f"{host.hostname}:{host.port}",
            "credential_id": None,
            "platform": host_platform(host.os_type),
            "checks": [_check("auth", "fail", "no_credential")],
            "duration_ms": 0,
        }

    return run_preflight_probe(
        hostname=host.hostname,
        port=host.port,
        os_type=host.os_type,
        credential=cred,
        settings=settings,
        known_hosts_entry=getattr(host, "ssh_known_hosts_entry", None),
    )
