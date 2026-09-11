"""AuditFlow nmap + credential probe + profile matching (Celery worker)."""

from __future__ import annotations

import os
import subprocess
import tempfile
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from concurrent.futures import TimeoutError as FuturesTimeout
from datetime import UTC, datetime
from io import StringIO
from pathlib import Path

from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session, selectinload, sessionmaker

from app.logging_pub import publish_audit_flow_log
from secaudit_core.audit_flow_inventory import persist_audit_flow_hosts_to_inventory
from secaudit_core.audit_flow_match import (
    Fingerprint,
    ProfileMatchInput,
    decide_profile,
    detect_family,
    fingerprint_from_facts,
    merge_extra_profiles,
    pretty_fingerprint,
    rank_application_profiles,
    review_skip_without_auth,
    sanitize_probe_text,
)
from secaudit_core.ssh_fingerprint import fingerprint_from_known_hosts_line, scan_ssh_host_key, verify_or_pin_host_key
from secaudit_core.audit_flow_nmap import (
    NMAP_AUDITFLOW_DISCOVERY,
    NMAP_AUDITFLOW_IDENTITY,
    NMAP_AUDITFLOW_IDENTITY_NO_OS,
    PORT_SCAN_CHUNK_SIZE,
    has_management_port,
    merge_auditflow_hosts,
    parse_nmap_gnmap_hosts,
    parse_nmap_service_xml,
    services_blob,
)
from secaudit_core.inventory_scan import (
    ScanCancelledError,
    parse_nmap_discovery_xml,
)
from secaudit_core.audit_flow_state import (
    clear_audit_flow_state,
    is_audit_flow_cancelled,
    set_audit_flow_pid,
    set_audit_flow_progress,
)
from secaudit_core.enums import AuditFlowStatus, CredentialType
from secaudit_core.models import AuditFlowHost, AuditFlowRun, Category, Profile
from secaudit_core.profiles_catalog import infer_platform as platform_from_slug
from secaudit_core.secrets import decrypt_secret
from secaudit_core.credential_auth import decrypt_credential_key_passphrase
from secaudit_core.settings import SecAuditSettings


_NMAP_WALL_TIMEOUT = 180


def _cancelled(redis_url: str, run_id: int) -> None:
    if is_audit_flow_cancelled(redis_url, run_id):
        raise ScanCancelledError()


def _log(run_id: int, message: str, level: str = "info") -> None:
    publish_audit_flow_log(run_id, message, level=level)


def _host_by_ip(db: Session, run_id: int, ip: str) -> AuditFlowHost | None:
    return db.execute(
        select(AuditFlowHost).where(AuditFlowHost.run_id == run_id, AuditFlowHost.ip_address == ip)
    ).scalar_one_or_none()


def _ensure_host(db: Session, run_id: int, ip: str, hostname: str | None = None) -> AuditFlowHost:
    row = _host_by_ip(db, run_id, ip)
    if row is None:
        row = AuditFlowHost(
            run_id=run_id,
            ip_address=ip,
            hostname=hostname,
            skip_reason="scanning",
        )
        db.add(row)
        db.flush()
        return row
    if hostname and not row.hostname:
        row.hostname = hostname
    return row


def _refresh_hosts_found(db: Session, run: AuditFlowRun) -> None:
    run.hosts_found = int(
        db.execute(
            select(func.count()).select_from(AuditFlowHost).where(AuditFlowHost.run_id == run.id)
        ).scalar_one()
        or 0
    )


def _apply_nmap_identity(db: Session, run_id: int, discovered_ips: dict[str, str | None], service_hosts: dict) -> None:
    for ip, hostname in discovered_ips.items():
        _ensure_host(db, run_id, ip, hostname)
    for ip, nmap_host in service_hosts.items():
        hostname = nmap_host.get("hostname") or discovered_ips.get(ip)
        if hostname:
            discovered_ips[ip] = hostname
        row = _ensure_host(db, run_id, ip, hostname)
        ports = nmap_host.get("open_ports") or []
        if ports:
            row.open_ports = ",".join(str(p) for p in ports)
        blob = services_blob(nmap_host)
        if blob:
            row.nmap_services = blob[:2000]
        fp = fingerprint_from_facts(
            platform=None,
            nmap_os=nmap_host.get("os_guess"),
            services=blob,
            open_ports=ports,
        )
        if fp.get("platform"):
            row.platform = fp["platform"]
        pretty = pretty_fingerprint(fp) or nmap_host.get("os_guess")
        if pretty:
            row.os_guess = str(pretty)[:256]


def _identify_live_chunk(chunk: list[str], run_id: int, redis_url: str) -> dict:
    """OS/service nmap on hosts that already answered ping."""
    try:
        xml = _run_nmap([*NMAP_AUDITFLOW_IDENTITY, *chunk], run_id, redis_url)
        parsed = parse_nmap_service_xml(xml)
        if parsed:
            return parsed
    except RuntimeError as exc:
        _log(run_id, f"OS fingerprint unavailable, retrying services only: {exc}", "warning")
    xml = _run_nmap([*NMAP_AUDITFLOW_IDENTITY_NO_OS, *chunk], run_id, redis_url)
    return parse_nmap_service_xml(xml)


def _run_nmap(
    args: list[str],
    run_id: int,
    redis_url: str,
    on_hosts: Callable[[list[tuple[str, str | None]]], None] | None = None,
) -> str:
    if is_audit_flow_cancelled(redis_url, run_id):
        raise ScanCancelledError()
    xml_path = None
    gnmap_path = None
    err_path = None
    err_handle = None
    seen: set[str] = set()

    def _emit_new_hosts() -> None:
        if on_hosts is None or not gnmap_path:
            return
        try:
            text = Path(gnmap_path).read_text(encoding="utf-8", errors="replace")
        except OSError:
            return
        batch: list[tuple[str, str | None]] = []
        for ip, hostname in parse_nmap_gnmap_hosts(text):
            if ip in seen:
                continue
            seen.add(ip)
            batch.append((ip, hostname))
        if batch:
            on_hosts(batch)

    try:
        with tempfile.NamedTemporaryFile(prefix=f"auditflow-nmap-{run_id}-", suffix=".xml", delete=False) as handle:
            xml_path = handle.name
        with tempfile.NamedTemporaryFile(prefix=f"auditflow-nmap-{run_id}-", suffix=".gnmap", delete=False) as handle:
            gnmap_path = handle.name
        err_handle = tempfile.NamedTemporaryFile(
            prefix=f"auditflow-nmap-{run_id}-", suffix=".err", delete=False, mode="w+b"
        )
        err_path = err_handle.name
        proc = subprocess.Popen(
            ["nmap", *args, "-oX", xml_path, "-oG", gnmap_path],
            stdout=subprocess.DEVNULL,
            stderr=err_handle,
        )
        set_audit_flow_pid(redis_url, run_id, proc.pid)
        _log(run_id, f"Starting nmap {' '.join(args)}")
        last_heartbeat = time.monotonic()
        started = last_heartbeat
        try:
            while proc.poll() is None:
                if is_audit_flow_cancelled(redis_url, run_id):
                    proc.terminate()
                    try:
                        proc.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait()
                    raise ScanCancelledError()
                _emit_new_hosts()
                if time.monotonic() - started >= _NMAP_WALL_TIMEOUT:
                    _log(run_id, f"nmap timed out after {_NMAP_WALL_TIMEOUT}s, stopping", "warning")
                    proc.terminate()
                    try:
                        proc.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait()
                    break
                if time.monotonic() - last_heartbeat >= 8:
                    _log(run_id, f"nmap still running: {' '.join(args[:6])}")
                    last_heartbeat = time.monotonic()
                time.sleep(0.5)
            _emit_new_hosts()
            stderr = Path(err_path).read_text(encoding="utf-8", errors="replace")
            xml_text = Path(xml_path).read_text(encoding="utf-8", errors="replace")
            if proc.returncode not in (0,) and not xml_text.strip():
                raise RuntimeError(stderr.strip() or f"nmap exited with code {proc.returncode}")
            return xml_text
        finally:
            pass
    finally:
        if err_handle is not None:
            try:
                err_handle.close()
            except OSError:
                pass
        for path in (xml_path, gnmap_path, err_path):
            if path:
                try:
                    os.unlink(path)
                except OSError:
                    pass


def _load_ssh_key(secret: str, passphrase: str | None = None):
    import paramiko

    for cls in (paramiko.RSAKey, paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.DSSKey):
        try:
            return cls.from_private_key(StringIO(secret), password=passphrase)
        except Exception:
            continue
    raise ValueError("Unsupported SSH key")


def _profile_inputs(db: Session) -> list[ProfileMatchInput]:
    rows = db.execute(
        select(Profile, Category.slug)
        .outerjoin(Category, Profile.category_id == Category.id)
        .where(Profile.is_active.is_(True))
    ).all()
    items: list[ProfileMatchInput] = []
    for profile, slug in rows:
        items.append(
            {
                "id": profile.id,
                "profile_name": profile.profile_name,
                "os_name": profile.os_name,
                "os_version": profile.os_version,
                "os_vendor": profile.os_vendor,
                "platform": platform_from_slug(slug or ""),
                "category_slug": slug or "",
            }
        )
    return items


_SSH_LINUX_FACTS = (
    "cat /etc/os-release /usr/lib/os-release 2>/dev/null; echo; "
    "cat /etc/redhat-release /etc/SuSE-release /etc/suse-release 2>/dev/null; echo; "
    "cat /etc/astra_version 2>/dev/null; echo; "
    "cat /etc/openwrt_release 2>/dev/null; echo; "
    "hostnamectl 2>/dev/null | head -n 12; echo; "
    "uname -srm 2>/dev/null"
)
_SSH_NETWORK_FACTS = "show version"

_FAMILY_DEVICE_TYPES = {
    "cisco": ("cisco_ios", "cisco_xe", "cisco_nxos"),
    "juniper": ("juniper_junos",),
    "mikrotik": ("mikrotik_routeros",),
    "eltex": ("cisco_ios",),
    "huawei": ("huawei",),
    "fortinet": ("fortinet",),
    "arista": ("arista_eos",),
    "paloalto": ("paloalto_panos",),
}
_NETWORK_COMMANDS = {
    "cisco": ("show version",),
    "juniper": ("show version",),
    "mikrotik": ("/system resource print",),
    "eltex": ("show version",),
    "huawei": ("display version",),
    "fortinet": ("get system status",),
    "arista": ("show version",),
    "paloalto": ("show system info",),
}

_REPROBE_SKIP = frozenset({"auth_failed", "unreachable"})
_PROBE_HOST_TIMEOUT = 18
_PROBE_WORKERS = 8


def _use_netmiko(open_ports: list[int], services_text: str) -> bool:
    family = detect_family(services_text)
    ports = set(open_ports)
    return family in _FAMILY_DEVICE_TYPES or bool(ports & {23, 830})


def _ssh_exec(client, command: str) -> str:
    _, stdout, stderr = client.exec_command(command, timeout=8)
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    text = sanitize_probe_text(out) or sanitize_probe_text(err)
    return text[:4000]


def _looks_like_linux_facts(text: str) -> bool:
    blob = (text or "").lower()
    return (
        "id=" in blob
        or "pretty_name=" in blob
        or "name=" in blob
        or "distrib_id=" in blob
        or "operating system:" in blob
        or blob.startswith("linux ")
    )


class _PinningHostKeyPolicy:
    """TOFU on first probe; reject a different key once a fingerprint is pinned."""

    def __init__(self, expected_fingerprint: str | None = None):
        self.expected_fingerprint = expected_fingerprint
        self.fingerprint: str | None = None
        self.entry: str | None = None

    def missing_host_key(self, client, hostname, key):
        import paramiko

        try:
            fingerprint, entry = verify_or_pin_host_key(
                hostname=hostname,
                key_type=key.get_name(),
                key_b64=key.get_base64(),
                expected_fingerprint=self.expected_fingerprint,
            )
        except ValueError as exc:
            raise paramiko.SSHException(str(exc)) from exc
        self.fingerprint = fingerprint
        self.entry = entry
        client.get_host_keys().add(hostname, key.get_name(), key)


def _host_key_from_paramiko(client, ip: str) -> tuple[str | None, str | None]:
    try:
        transport = client.get_transport()
        if transport is None:
            return None, None
        key = transport.get_remote_server_key()
        entry = f"{ip} {key.get_name()} {key.get_base64()}"
        return fingerprint_from_known_hosts_line(entry), entry
    except Exception:
        return None, None


def _scan_host_key(ip: str, port: int = 22) -> tuple[str | None, str | None]:
    try:
        return scan_ssh_host_key(ip, port, timeout=8)
    except Exception:
        return None, None


def _apply_known_hosts(client, entry: str, ip: str) -> None:
    from paramiko.hostkeys import HostKeyEntry

    parsed = HostKeyEntry.from_line(entry.strip())
    if parsed is None or parsed.key is None:
        return
    names = set(parsed.hostnames or [])
    names.add(ip)
    for name in names:
        client.get_host_keys().add(name, parsed.key.get_name(), parsed.key)


def _prepare_ssh_client(client, ip: str, known_hosts: str | None):
    entry = (known_hosts or "").strip() or None
    expected_fp = None
    if entry:
        try:
            expected_fp = fingerprint_from_known_hosts_line(entry)
        except ValueError:
            entry = None
    if entry:
        try:
            _apply_known_hosts(client, entry, ip)
        except Exception:
            pass
    policy = _PinningHostKeyPolicy(expected_fp)
    client.set_missing_host_key_policy(policy)
    return policy


def _credential_type(cred) -> CredentialType | None:
    value = cred.credential_type
    if isinstance(value, CredentialType):
        return value
    try:
        return CredentialType(str(value))
    except ValueError:
        return None


def _ssh_auth_error(exc: BaseException) -> str:
    import paramiko

    auth_errors = [paramiko.AuthenticationException]
    bad_type = getattr(paramiko, "BadAuthenticationType", None)
    if bad_type is not None:
        auth_errors.append(bad_type)
    if isinstance(exc, tuple(auth_errors)):
        return "auth_failed"
    text = str(exc).lower()
    if "authentication" in text or "permission denied" in text or "auth fail" in text:
        return "auth_failed"
    return "unreachable"


def _try_keyboard_interactive(client, username: str, secret: str) -> bool:
    import paramiko

    transport = client.get_transport()
    if transport is None or not transport.is_active():
        return False

    def handler(_title, _instructions, prompt_list):
        return [secret for _ in prompt_list]

    try:
        transport.auth_interactive(username, handler)
    except (paramiko.AuthenticationException, paramiko.SSHException):
        return False
    return bool(transport.is_authenticated())


def _probe_ssh(
    ip: str,
    username: str,
    secret: str,
    *,
    key: bool,
    known_hosts: str | None = None,
    key_passphrase: str | None = None,
) -> tuple[str | None, str | None, str | None, str | None]:
    """Return (facts, fingerprint, known_hosts, error). Empty facts still mean login OK."""
    import paramiko

    client = paramiko.SSHClient()
    # Only pin a key from a previous successful probe. Pre-scanning with
    # ssh-keyscan often stores a different algorithm than Paramiko negotiates,
    # which was reported as a wrong password.
    policy = _prepare_ssh_client(client, ip, known_hosts)
    try:
        kwargs: dict = {
            "hostname": ip,
            "username": username,
            "timeout": 12,
            "auth_timeout": 12,
            "banner_timeout": 12,
            "allow_agent": False,
            "look_for_keys": False,
        }
        if key:
            kwargs["pkey"] = _load_ssh_key(secret, passphrase=key_passphrase)
        else:
            kwargs["password"] = secret
        try:
            client.connect(**kwargs)
        except paramiko.AuthenticationException:
            if key or not _try_keyboard_interactive(client, username, secret):
                return None, None, None, "auth_failed"
        transport = client.get_transport()
        if transport is None or not transport.is_authenticated():
            if key or not _try_keyboard_interactive(client, username, secret):
                return None, None, None, "auth_failed"
        fingerprint, entry = _host_key_from_paramiko(client, ip)
        fingerprint = fingerprint or policy.fingerprint
        entry = entry or policy.entry
        linux = _ssh_exec(client, _SSH_LINUX_FACTS)
        if _looks_like_linux_facts(linux):
            return linux, fingerprint, entry, None
        network = _ssh_exec(client, _SSH_NETWORK_FACTS)
        combined = "\n".join(part for part in (linux, network) if part).strip()
        return combined, fingerprint, entry, None
    except Exception as exc:
        return None, None, None, _ssh_auth_error(exc)
    finally:
        try:
            client.close()
        except Exception:
            pass


def _network_device_types(blob: str, family: str | None) -> list[str]:
    ordered: list[str] = []
    if family and family in _FAMILY_DEVICE_TYPES:
        ordered.extend(_FAMILY_DEVICE_TYPES[family])
    lower = (blob or "").lower()
    hints = (
        ("mikrotik", "mikrotik_routeros"),
        ("routeros", "mikrotik_routeros"),
        ("junos", "juniper_junos"),
        ("juniper", "juniper_junos"),
        ("huawei", "huawei"),
        ("fortinet", "fortinet"),
        ("fortigate", "fortinet"),
        ("arista", "arista_eos"),
        ("palo alto", "paloalto_panos"),
        ("cisco", "cisco_ios"),
        ("eltex", "cisco_ios"),
        ("xiaomi", "cisco_ios"),
        ("xiaoqiang", "cisco_ios"),
        ("openwrt", "cisco_ios"),
    )
    for needle, device_type in hints:
        if needle in lower:
            ordered.append(device_type)
    unique: list[str] = []
    for item in ordered:
        if item not in unique:
            unique.append(item)
    return unique[:3] or ["cisco_ios", "mikrotik_routeros", "juniper_junos"]


def _probe_netmiko(
    ip: str,
    username: str,
    secret: str,
    *,
    blob: str,
    family: str | None,
    port: int = 22,
) -> str | None:
    try:
        from netmiko import ConnectHandler
    except ImportError:
        return None
    commands = _NETWORK_COMMANDS.get(family or "", ("show version",))
    for device_type in _network_device_types(blob, family):
        try:
            with ConnectHandler(
                device_type=device_type,
                host=ip,
                port=port,
                username=username,
                password=secret,
                timeout=8,
                conn_timeout=8,
                auth_timeout=8,
                banner_timeout=8,
            ) as connection:
                chunks: list[str] = []
                for command in commands:
                    try:
                        chunks.append(connection.send_command(command, read_timeout=8))
                    except Exception:
                        continue
                text = "\n".join(part for part in chunks if part).strip()
                if text:
                    return text[:4000]
        except Exception:
            continue
    return None


_WINRM_FACTS_PS = (
    "$os = Get-CimInstance Win32_OperatingSystem; "
    "Write-Output $os.Caption; "
    "Write-Output ('Version=' + $os.Version); "
    "Write-Output ('ProductType=' + $os.ProductType); "
    "Write-Output ('BuildNumber=' + $os.BuildNumber)"
)


def _probe_winrm(ip: str, username: str, secret: str, *, ports: set[int] | None = None) -> str | None:
    try:
        import winrm
    except ImportError:
        return None
    endpoints: list[str] = []
    open_ports = ports or set()
    if 5986 in open_ports:
        endpoints.append(f"https://{ip}:5986/wsman")
    if 5985 in open_ports or not open_ports:
        endpoints.append(f"http://{ip}:5985/wsman")
    if not endpoints:
        endpoints.append(f"http://{ip}:5985/wsman")
    for endpoint in endpoints:
        try:
            session = winrm.Session(
                endpoint,
                auth=(username, secret),
                transport="ntlm",
                server_cert_validation="ignore",
            )
            result = session.run_ps(_WINRM_FACTS_PS)
            if result.status_code != 0:
                continue
            text = (result.std_out or b"").decode("utf-8", errors="replace").strip()
            if text:
                return text[:2000]
        except Exception:
            continue
    return None


def _try_credentials(
    ip: str,
    creds: list,
    settings: SecAuditSettings,
    open_ports: list[int],
    *,
    services_text: str = "",
    known_hosts: str | None = None,
    log: Callable[[str, str], None] | None = None,
) -> tuple[int | None, Fingerprint | None, str | None, str | None, str | None]:
    def _note(message: str, level: str = "info") -> None:
        if log:
            log(message, level)

    if not creds:
        return None, None, None, None, None

    ports = set(open_ports)
    last_error = "auth_failed"
    guessed_family = detect_family(services_text)
    networkish = _use_netmiko(open_ports, services_text)
    pinned = (known_hosts or "").strip() or None
    for cred in creds:
        secret = decrypt_secret(cred.encrypted_secret, settings).replace("\r\n", "\n").rstrip("\n").rstrip("\r")
        ctype = _credential_type(cred)
        if ctype is None:
            _note(f"{ip}: skip credential {cred.username}: unsupported type {cred.credential_type}", "warning")
            continue
        label = cred.label or cred.username
        if ctype == CredentialType.WINRM and ports & {5985, 5986, 445, 3389}:
            _note(f"{ip}: trying WinRM as {cred.username} ({label})")
            output = _probe_winrm(ip, cred.username, secret, ports=ports)
            if output:
                fp = fingerprint_from_facts(platform="windows", win_caption=output, open_ports=open_ports)
                return cred.id, fp, None, None, None
            _note(f"{ip}: WinRM login failed for {cred.username}", "warning")
        elif ctype in {CredentialType.SSH_PASSWORD, CredentialType.SSH_KEY} and (
            not ports or 22 in ports or 23 in ports
        ):
            if ctype == CredentialType.SSH_PASSWORD and networkish:
                _note(f"{ip}: trying network CLI as {cred.username} ({label})")
                net_out = _probe_netmiko(
                    ip, cred.username, secret, blob=services_text, family=guessed_family
                )
                if net_out:
                    fp = fingerprint_from_facts(platform="network", os_release=net_out, open_ports=open_ports)
                    fingerprint, entry = _pinned_or_scanned_host_key(ip, pinned)
                    return cred.id, fp, None, fingerprint, entry
            _note(f"{ip}: trying SSH as {cred.username} ({label})")
            key_passphrase = (
                decrypt_credential_key_passphrase(cred, settings)
                if ctype == CredentialType.SSH_KEY
                else None
            )
            output, fingerprint, entry, ssh_error = _probe_ssh(
                ip,
                cred.username,
                secret,
                key=ctype == CredentialType.SSH_KEY,
                known_hosts=pinned,
                key_passphrase=key_passphrase,
            )
            if ssh_error is None:
                fp = fingerprint_from_facts(platform=None, os_release=output, open_ports=open_ports)
                return cred.id, fp, None, fingerprint, entry
            last_error = ssh_error
            if ssh_error == "auth_failed":
                _note(f"{ip}: SSH login failed for {cred.username}", "warning")
            else:
                _note(f"{ip}: SSH not reachable for {cred.username}", "warning")
        time.sleep(0.2)
    if 22 not in ports and not (ports & {5985, 5986}):
        last_error = "unreachable"
    return None, None, last_error, None, None


def _try_credentials_timed(
    ip: str,
    creds: list,
    settings: SecAuditSettings,
    open_ports: list[int],
    *,
    services_text: str = "",
    known_hosts: str | None = None,
    log: Callable[[str, str], None] | None = None,
) -> tuple[int | None, Fingerprint | None, str | None, str | None, str | None]:
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(
            _try_credentials,
            ip,
            creds,
            settings,
            open_ports,
            services_text=services_text,
            known_hosts=known_hosts,
            log=log,
        )
        try:
            return future.result(timeout=_PROBE_HOST_TIMEOUT)
        except FuturesTimeout:
            if log:
                log(f"{ip}: probe timed out after {_PROBE_HOST_TIMEOUT}s", "warning")
            return None, None, "unreachable", None, None


def _pinned_or_scanned_host_key(ip: str, pinned: str | None) -> tuple[str | None, str | None]:
    if pinned:
        try:
            return fingerprint_from_known_hosts_line(pinned), pinned
        except ValueError:
            pass
    return _scan_host_key(ip)


def _apply_probe_result(
    row: AuditFlowHost,
    *,
    hostname: str | None,
    open_ports: list[int],
    blob: str,
    nmap_os: str | None,
    cred_id: int | None,
    auth_fp: Fingerprint | None,
    skip: str | None,
    fingerprint: str | None,
    known_hosts: str | None,
    profiles: list[ProfileMatchInput],
) -> dict:
    fp = fingerprint_from_facts(
        platform=auth_fp.get("platform") if auth_fp else None,
        os_release=(
            auth_fp.get("raw") if auth_fp and auth_fp.get("platform") != "windows" else None
        ),
        win_caption=(
            auth_fp.get("raw") if auth_fp and auth_fp.get("platform") == "windows" else None
        ),
        nmap_os=nmap_os,
        services=blob,
        open_ports=open_ports,
    )
    decision = decide_profile(fp, profiles, authenticated=bool(cred_id))
    apps = rank_application_profiles(services=blob, open_ports=open_ports, profiles=profiles)
    row.hostname = hostname or row.hostname
    row.platform = fp.get("platform")
    row.os_guess = pretty_fingerprint(fp) or nmap_os
    row.open_ports = ",".join(str(p) for p in open_ports) if open_ports else row.open_ports
    row.nmap_services = blob[:2000] if blob else row.nmap_services
    row.credential_id = cred_id
    row.profile_id = decision["profile_id"]
    row.profile_name = decision["profile_name"]
    row.confidence = decision["confidence"]
    row.alternatives_json = decision["alternatives"]
    row.extra_profiles_json = merge_extra_profiles(row.extra_profiles_json, apps)
    if fingerprint:
        row.ssh_host_key_fingerprint = fingerprint
    if known_hosts:
        row.ssh_known_hosts_entry = known_hosts
    if not cred_id:
        row.selected = False
        discovered = bool(open_ports or nmap_os or blob or hostname)
        row.skip_reason, row.skip_detail = review_skip_without_auth(
            probe_skip=skip,
            has_profile=bool(decision.get("profile_id")),
            discovered=discovered,
        )
    else:
        row.selected = decision["auto_select"]
        row.skip_reason = decision["skip_reason"]
        row.skip_detail = decision["skip_detail"]
    if row.os_guess and len(row.os_guess) > 256:
        row.os_guess = row.os_guess[:256]
    return decision


def _log_match(run_id: int, ip: str, cred_id: int | None, skip: str | None, decision: dict, extras: list | None) -> None:
    extra_labels = [item.get("profile_name") or item.get("label") for item in (extras or []) if item.get("selected")]
    extra_note = f"; apps: {', '.join(extra_labels)}" if extra_labels else ""
    if cred_id and decision.get("auto_select"):
        _log(
            run_id,
            f"{ip}: matched {decision.get('profile_name')} ({decision.get('confidence')}%){extra_note}",
        )
    elif not cred_id and decision.get("profile_name"):
        _log(
            run_id,
            f"{ip}: available, suggested {decision.get('profile_name')} ({decision.get('confidence')}%){extra_note}",
        )
    elif not cred_id:
        _log(run_id, f"{ip}: {skip or 'no_matching_profile'}", level="warning")
    elif decision.get("profile_name"):
        _log(
            run_id,
            f"{ip}: suggested {decision.get('profile_name')} ({decision.get('confidence')}%) — {decision.get('skip_reason')}{extra_note}",
            level="warning",
        )
    else:
        _log(run_id, f"{ip}: no matching profile{extra_note}", level="warning")


def run_audit_flow_scan_sync(run_id: int, *, database_url: str, redis_url: str) -> None:
    engine = create_engine(database_url)
    SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)
    settings = SecAuditSettings()
    try:
        with SessionLocal() as db:
            run = db.get(AuditFlowRun, run_id)
            if run is None:
                return
            run.status = AuditFlowStatus.SCANNING
            run.started_at = datetime.now(UTC)
            db.commit()
            _log(run_id, f"Task #{run_id} started")
            first_target = (run.targets_json or [None])[0]
            set_audit_flow_progress(redis_url, run_id, phase="queued", target=first_target, address=first_target)

            discovered_ips: dict[str, str | None] = {}
            service_hosts: dict = {}
            try:
                live_ips: list[str] = []
                for target in run.targets_json or []:
                    _cancelled(redis_url, run_id)
                    set_audit_flow_progress(
                        redis_url, run_id, phase="discovery", target=target, address=target
                    )
                    _log(run_id, f"Ping sweep {target}")
                    xml = _run_nmap([*NMAP_AUDITFLOW_DISCOVERY, target], run_id, redis_url)
                    ping_live = parse_nmap_discovery_xml(xml, skip_unreliable=True)
                    _log(run_id, f"Ping replies: {len(ping_live)} host(s) in {target}")
                    for host in ping_live:
                        ip = host["ip"]
                        if ip in discovered_ips:
                            continue
                        discovered_ips[ip] = host.get("hostname")
                        live_ips.append(ip)
                        _ensure_host(db, run_id, ip, host.get("hostname"))
                    if ping_live:
                        _log(run_id, "Live: " + ", ".join(host["ip"] for host in ping_live))
                    _refresh_hosts_found(db, run)
                    db.commit()

                if live_ips:
                    _cancelled(redis_url, run_id)
                    _log(run_id, f"OS/service scan on {len(live_ips)} live host(s)")
                    for index in range(0, len(live_ips), PORT_SCAN_CHUNK_SIZE):
                        chunk = live_ips[index : index + PORT_SCAN_CHUNK_SIZE]
                        set_audit_flow_progress(
                            redis_url, run_id, phase="services", target=None, address=chunk[0]
                        )
                        _log(run_id, f"Identifying {', '.join(chunk)}")
                        parsed = _identify_live_chunk(chunk, run_id, redis_url)
                        for ip, nmap_host in parsed.items():
                            service_hosts[ip] = merge_auditflow_hosts(service_hosts.get(ip), nmap_host)
                            if nmap_host.get("hostname"):
                                discovered_ips[ip] = nmap_host["hostname"]

                _apply_nmap_identity(db, run_id, discovered_ips, service_hosts)
                _refresh_hosts_found(db, run)
                db.commit()
                _log(run_id, f"Identified {len(service_hosts)} host(s), {len(discovered_ips)} live")

                profiles = _profile_inputs(db)
                creds = list(run.credentials)
                ips = sorted(set(discovered_ips) | set(service_hosts))
                probe_ips: list[str] = []
                for ip in ips:
                    nmap_host = service_hosts.get(ip)
                    open_ports = nmap_host["open_ports"] if nmap_host else []
                    hostname = (nmap_host or {}).get("hostname") or discovered_ips.get(ip)
                    if has_management_port(open_ports):
                        probe_ips.append(ip)
                        continue
                    row = _ensure_host(db, run_id, ip, hostname)
                    blob = services_blob(nmap_host) if nmap_host else ""
                    nmap_os = nmap_host.get("os_guess") if nmap_host else None
                    decision = _apply_probe_result(
                        row,
                        hostname=hostname,
                        open_ports=open_ports,
                        blob=blob,
                        nmap_os=nmap_os,
                        cred_id=None,
                        auth_fp=None,
                        skip="unreachable",
                        fingerprint=None,
                        known_hosts=None,
                        profiles=profiles,
                    )
                    _log_match(run_id, ip, None, row.skip_reason, decision, row.extra_profiles_json)
                _refresh_hosts_found(db, run)
                db.commit()
                if creds:
                    _log(run_id, f"Probing {len(probe_ips)} management host(s)")
                else:
                    _log(run_id, "No credentials provided; skipping login probe")

                def _probe_one(ip: str):
                    nmap_host = service_hosts.get(ip)
                    open_ports = nmap_host["open_ports"] if nmap_host else []
                    blob = services_blob(nmap_host) if nmap_host else ""
                    return ip, _try_credentials_timed(
                        ip,
                        creds,
                        settings,
                        open_ports,
                        services_text=blob,
                        log=lambda message, level="info": _log(run_id, message, level),
                    )

                if probe_ips and creds:
                    with ThreadPoolExecutor(max_workers=_PROBE_WORKERS) as pool:
                        futures = [pool.submit(_probe_one, ip) for ip in probe_ips]
                        for future in as_completed(futures):
                            _cancelled(redis_url, run_id)
                            ip, probe = future.result()
                            cred_id, auth_fp, skip, fingerprint, known_hosts = probe
                            nmap_host = service_hosts.get(ip)
                            open_ports = nmap_host["open_ports"] if nmap_host else []
                            hostname = (nmap_host or {}).get("hostname") or discovered_ips.get(ip)
                            blob = services_blob(nmap_host) if nmap_host else ""
                            nmap_os = nmap_host.get("os_guess") if nmap_host else None
                            row = _ensure_host(db, run_id, ip, hostname)
                            set_audit_flow_progress(redis_url, run_id, phase="probe", target=None, address=ip)
                            decision = _apply_probe_result(
                                row,
                                hostname=hostname,
                                open_ports=open_ports,
                                blob=blob,
                                nmap_os=nmap_os,
                                cred_id=cred_id,
                                auth_fp=auth_fp,
                                skip=skip,
                                fingerprint=fingerprint,
                                known_hosts=known_hosts,
                                profiles=profiles,
                            )
                            _log_match(run_id, ip, cred_id, skip, decision, row.extra_profiles_json)
                            _refresh_hosts_found(db, run)
                            db.commit()
                elif probe_ips:
                    for ip in probe_ips:
                        _cancelled(redis_url, run_id)
                        nmap_host = service_hosts.get(ip)
                        open_ports = nmap_host["open_ports"] if nmap_host else []
                        hostname = (nmap_host or {}).get("hostname") or discovered_ips.get(ip)
                        blob = services_blob(nmap_host) if nmap_host else ""
                        nmap_os = nmap_host.get("os_guess") if nmap_host else None
                        row = _ensure_host(db, run_id, ip, hostname)
                        set_audit_flow_progress(redis_url, run_id, phase="probe", target=None, address=ip)
                        decision = _apply_probe_result(
                            row,
                            hostname=hostname,
                            open_ports=open_ports,
                            blob=blob,
                            nmap_os=nmap_os,
                            cred_id=None,
                            auth_fp=None,
                            skip=None,
                            fingerprint=None,
                            known_hosts=None,
                            profiles=profiles,
                        )
                        _log_match(run_id, ip, None, None, decision, row.extra_profiles_json)
                        _refresh_hosts_found(db, run)
                        db.commit()

                run = db.get(AuditFlowRun, run_id)
                if run:
                    _refresh_hosts_found(db, run)
                    if run.save_to_inventory:
                        saved = persist_audit_flow_hosts_to_inventory(db, run)
                        _log(run_id, f"Saved {saved} host(s) to inventory")
                    run.status = AuditFlowStatus.READY
                    run.finished_at = datetime.now(UTC)
                    db.commit()
                    _log(run_id, f"Scan finished: {run.hosts_found} host(s)")
            except ScanCancelledError:
                run = db.get(AuditFlowRun, run_id)
                if run:
                    run.status = AuditFlowStatus.CANCELLED
                    run.finished_at = datetime.now(UTC)
                    run.error_message = "Cancelled by user"
                    db.commit()
                _log(run_id, "Task cancelled", level="warning")
            except Exception as exc:
                run = db.get(AuditFlowRun, run_id)
                if run:
                    run.status = AuditFlowStatus.FAILED
                    run.finished_at = datetime.now(UTC)
                    run.error_message = str(exc)[:2000]
                    db.commit()
                _log(run_id, f"Scan failed: {exc}", level="error")
    finally:
        clear_audit_flow_state(redis_url, run_id)
        engine.dispose()


def _ports_from_row(row: AuditFlowHost) -> list[int]:
    if not row.open_ports:
        return []
    return [int(p) for p in row.open_ports.split(",") if p.strip().isdigit()]


def run_audit_flow_reprobe_sync(
    run_id: int,
    *,
    database_url: str,
    redis_url: str,
    credential_id: int | None = None,
    host_ids: list[int] | None = None,
) -> None:
    """Retry credential probe on hosts that failed auth after the scan finished."""
    engine = create_engine(database_url)
    SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)
    settings = SecAuditSettings()
    try:
        with SessionLocal() as db:
            run = db.execute(
                select(AuditFlowRun)
                .options(selectinload(AuditFlowRun.hosts), selectinload(AuditFlowRun.credentials))
                .where(AuditFlowRun.id == run_id)
            ).scalar_one_or_none()
            if run is None:
                return
            run.status = AuditFlowStatus.SCANNING
            db.commit()
            _log(run_id, "Re-probing hosts with new credentials")
            profiles = _profile_inputs(db)
            creds = list(run.credentials)
            if credential_id:
                creds = [c for c in creds if c.id == credential_id] or creds
            targets = [
                row
                for row in run.hosts
                if not row.job_run_id
                and (
                    (host_ids is not None and row.id in host_ids)
                    or (
                        host_ids is None
                        and (
                            row.skip_reason in _REPROBE_SKIP
                            or row.skip_reason == "checking"
                            or not row.credential_id
                        )
                    )
                )
            ]
            try:
                for row in targets:
                    _cancelled(redis_url, run_id)
                    ip = row.ip_address
                    open_ports = _ports_from_row(row)
                    blob = row.nmap_services or ""
                    row.skip_reason = "checking"
                    db.commit()
                    set_audit_flow_progress(redis_url, run_id, phase="probe", target=None, address=ip)
                    _log(run_id, f"Re-probing {ip}")
                    cred_id, auth_fp, skip, fingerprint, known_hosts = _try_credentials_timed(
                        ip,
                        creds,
                        settings,
                        open_ports,
                        services_text=blob,
                        known_hosts=row.ssh_known_hosts_entry,
                        log=lambda message, level="info": _log(run_id, message, level),
                    )
                    decision = _apply_probe_result(
                        row,
                        hostname=row.hostname,
                        open_ports=open_ports,
                        blob=blob,
                        nmap_os=row.os_guess,
                        cred_id=cred_id,
                        auth_fp=auth_fp,
                        skip=skip,
                        fingerprint=fingerprint,
                        known_hosts=known_hosts,
                        profiles=profiles,
                    )
                    _log_match(run_id, ip, cred_id, skip, decision, row.extra_profiles_json)
                    db.commit()
                run = db.get(AuditFlowRun, run_id)
                if run:
                    run.status = AuditFlowStatus.READY
                    run.finished_at = datetime.now(UTC)
                    db.commit()
                _log(run_id, f"Re-probe finished ({len(targets)} host(s))")
            except ScanCancelledError:
                run = db.get(AuditFlowRun, run_id)
                if run:
                    run.status = AuditFlowStatus.CANCELLED
                    run.finished_at = datetime.now(UTC)
                    run.error_message = "Cancelled by user"
                    db.commit()
                _log(run_id, "Re-probe cancelled", level="warning")
            except Exception as exc:
                run = db.get(AuditFlowRun, run_id)
                if run:
                    run.status = AuditFlowStatus.READY
                    run.error_message = str(exc)[:2000]
                    db.commit()
                _log(run_id, f"Re-probe failed: {exc}", level="error")
    finally:
        clear_audit_flow_state(redis_url, run_id)
        engine.dispose()
