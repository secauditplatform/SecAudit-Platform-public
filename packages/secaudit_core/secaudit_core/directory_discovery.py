"""Read-only AD/LDAP computer discovery for the host inventory.

The directory is a source of computer names, not a second audit engine.
Existing nmap hosts are reused when the DNS name or short name already matches.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

MAX_COMPUTERS = 5000
_PAGE_SIZE = 500
_CONNECT_TIMEOUT = 10
_RECEIVE_TIMEOUT = 45
_WINRM_PORT = 5985
_SSH_PORT = 22

_COMPUTER_FILTER = "(&(objectCategory=computer)(objectClass=computer))"
_ENABLED_COMPUTER_FILTER = (
    "(&(objectCategory=computer)(objectClass=computer)"
    "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
)
_COMPUTER_ATTRIBUTES = (
    "cn",
    "dNSHostName",
    "operatingSystem",
    "distinguishedName",
    "userAccountControl",
)
_ACCOUNT_DISABLE = 0x2
_SKIP_OUS = frozenset({"computers", "domain controllers", "users", "builtin"})
_SERVER_RE = re.compile(
    r"^(?:(?:\d{1,3}\.){3}\d{1,3}|"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*)$"
)
_LINUX_MARKERS = ("linux", "ubuntu", "debian", "centos", "red hat", "rhel", "suse", "fedora")


class DirectoryDiscoveryError(Exception):
    """Safe to show to an operator. Never includes the bind password."""


class _MatchingRuleUnsupported(DirectoryDiscoveryError):
    pass


@dataclass
class DirectoryBind:
    server: str
    port: int
    use_ssl: bool
    start_tls: bool
    verify_tls: bool
    base_dn: str
    bind_dn: str
    password: str
    enabled_only: bool = True

    def __repr__(self) -> str:
        return (
            f"DirectoryBind(server={self.server!r}, port={self.port}, "
            f"bind_dn={self.bind_dn!r})"
        )


@dataclass
class DirectoryComputer:
    cn: str
    dns_hostname: str | None
    operating_system: str | None
    distinguished_name: str
    disabled: bool


@dataclass
class DirectorySearchResult:
    computers: list[DirectoryComputer]
    truncated: bool = False


@dataclass
class DirectoryProbeResult:
    computers: int
    sample: list[str] = field(default_factory=list)
    truncated: bool = False


@dataclass
class KnownHost:
    id: int
    name: str
    hostname: str
    os_type: str | None
    site: str | None


@dataclass
class PlannedCreate:
    name: str
    hostname: str
    port: int
    os_type: str
    site: str | None
    is_active: bool = True


@dataclass
class PlannedUpdate:
    host_id: int
    name: str | None = None
    os_type: str | None = None
    site: str | None = None


@dataclass
class DirectoryImportPlan:
    creates: list[PlannedCreate] = field(default_factory=list)
    updates: list[PlannedUpdate] = field(default_factory=list)
    matched_ids: list[int] = field(default_factory=list)


def public_error(text: str, password: str) -> str:
    cleaned = text.replace("\x00", " ")
    if password:
        cleaned = cleaned.replace(password, "***")
    return " ".join(cleaned.split())[:500]


def computer_filter(enabled_only: bool) -> str:
    return _ENABLED_COMPUTER_FILTER if enabled_only else _COMPUTER_FILTER


def normalize_directory_endpoint(
    *,
    server: str,
    port: int,
    use_ssl: bool,
    start_tls: bool,
    base_dn: str,
    bind_dn: str,
) -> tuple[str, int, str, str, bool]:
    """Validate a directory endpoint. Returns server, port, base DN, bind DN, start_tls."""
    host = server.strip()
    if not host or len(host) > 253 or not _SERVER_RE.fullmatch(host):
        raise ValueError("Directory server must be a hostname or IPv4 address")
    if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", host) and any(int(part) > 255 for part in host.split(".")):
        raise ValueError("Directory server must be a hostname or IPv4 address")
    if port < 1 or port > 65535:
        raise ValueError("Directory port must be between 1 and 65535")
    if use_ssl and start_tls:
        raise ValueError("StartTLS is used on port 389; turn it off when LDAPS is enabled")
    base = _normalize_dn(base_dn, label="Base DN")
    bind = _normalize_dn(bind_dn, label="Bind DN")
    return host, port, base, bind, start_tls and not use_ssl


def _normalize_dn(value: str, *, label: str) -> str:
    text = value.strip()
    if not text or len(text) > 512 or "=" not in text:
        raise ValueError(f"{label} must be an LDAP distinguished name")
    if any(ord(ch) < 32 for ch in text):
        raise ValueError(f"{label} contains unsupported characters")
    return text


def site_from_dn(distinguished_name: str) -> str | None:
    """First meaningful OU, skipping the default AD containers."""
    for part in _split_dn(distinguished_name):
        if "=" not in part:
            continue
        key, raw = part.split("=", 1)
        if key.strip().casefold() != "ou":
            continue
        name = _unescape_dn_value(raw)
        if not name or name.casefold() in _SKIP_OUS:
            continue
        return name[:64]
    return None


def os_type_from_operating_system(value: str | None) -> str:
    text = (value or "").casefold()
    if any(marker in text for marker in _LINUX_MARKERS):
        return "linux"
    return "windows"


def computer_from_attributes(attributes: dict, *, dn: str | None = None) -> DirectoryComputer | None:
    cn = (_first_str(attributes, "cn") or "").strip()
    dns = _clean_hostname(_first_str(attributes, "dNSHostName"))
    if not cn and dns:
        cn = dns.split(".", 1)[0]
    hostname = dns or _clean_hostname(cn)
    if not cn or hostname is None:
        return None
    distinguished = _first_str(attributes, "distinguishedName") or (dn or "")
    return DirectoryComputer(
        cn=cn[:128],
        dns_hostname=dns,
        operating_system=_first_str(attributes, "operatingSystem"),
        distinguished_name=distinguished,
        disabled=_is_disabled(_first_raw(attributes, "userAccountControl")),
    )


def plan_directory_import(
    computers: list[DirectoryComputer],
    known_hosts: list[KnownHost],
    *,
    aliases: dict[str, int] | None = None,
    map_ou_to_site: bool,
) -> DirectoryImportPlan:
    """Match directory computers to inventory hosts. Never touches another owner's rows."""
    by_id = {host.id: host for host in known_hosts}
    index: dict[str, int] = {}

    def remember(key: str | None, host_id: int) -> None:
        if not key:
            return
        lowered = key.strip().lower()
        if lowered and lowered not in index and host_id in by_id:
            index[lowered] = host_id

    for host in known_hosts:
        remember(host.hostname, host.id)
        remember(host.name, host.id)
    for alias, host_id in (aliases or {}).items():
        remember(alias, host_id)

    plan = DirectoryImportPlan()
    for computer in computers:
        host = _lookup_host(computer, index, by_id)
        if host is None:
            created = _plan_create(computer, map_ou_to_site=map_ou_to_site)
            if created is None:
                continue
            plan.creates.append(created)
            synthetic_id = -len(plan.creates)
            by_id[synthetic_id] = KnownHost(
                id=synthetic_id,
                name=created.name,
                hostname=created.hostname,
                os_type=created.os_type,
                site=created.site,
            )
            remember(created.hostname, synthetic_id)
            remember(created.name, synthetic_id)
            if computer.dns_hostname:
                remember(computer.dns_hostname, synthetic_id)
            continue
        if host.id < 0:
            continue
        if computer.disabled:
            plan.matched_ids.append(host.id)
            continue
        update = _plan_update(host, computer, map_ou_to_site=map_ou_to_site)
        if update is None:
            plan.matched_ids.append(host.id)
        else:
            plan.updates.append(update)
            if update.name is not None:
                host.name = update.name
            if update.os_type is not None:
                host.os_type = update.os_type
            if update.site is not None:
                host.site = update.site
            remember(host.name, host.id)
            remember(host.hostname, host.id)
    return plan


def probe_directory(bind: DirectoryBind) -> DirectoryProbeResult:
    result = search_computers(bind, limit=5)
    sample: list[str] = []
    for computer in result.computers[:5]:
        if computer.dns_hostname and computer.dns_hostname.casefold() != computer.cn.casefold():
            sample.append(f"{computer.cn} ({computer.dns_hostname})")
        else:
            sample.append(computer.cn)
    return DirectoryProbeResult(
        computers=len(result.computers),
        sample=sample,
        truncated=result.truncated or len(result.computers) >= 5,
    )


def search_computers(bind: DirectoryBind, *, limit: int = MAX_COMPUTERS) -> DirectorySearchResult:
    limit = max(1, min(limit, MAX_COMPUTERS))
    try:
        raw, truncated = _ldap_search(bind, computer_filter(bind.enabled_only), limit)
    except _MatchingRuleUnsupported:
        if not bind.enabled_only:
            raise
        raw, truncated = _ldap_search(bind, computer_filter(False), limit)
    computers: list[DirectoryComputer] = []
    for item in raw:
        computer = computer_from_attributes(item["attributes"], dn=item.get("dn"))
        if computer is None:
            continue
        if bind.enabled_only and computer.disabled:
            continue
        computers.append(computer)
        if len(computers) >= limit:
            truncated = True
            break
    return DirectorySearchResult(computers=computers, truncated=truncated)


def _ldap_search(bind: DirectoryBind, search_filter: str, limit: int) -> tuple[list[dict], bool]:
    try:
        import ssl

        from ldap3 import NONE, SUBTREE, Connection, Server, Tls
        from ldap3.core.exceptions import LDAPException
    except ImportError as exc:
        raise DirectoryDiscoveryError("LDAP client is not installed") from exc

    tls = Tls(validate=ssl.CERT_REQUIRED if bind.verify_tls else ssl.CERT_NONE)
    server = Server(
        bind.server,
        port=bind.port,
        use_ssl=bind.use_ssl,
        tls=tls,
        connect_timeout=_CONNECT_TIMEOUT,
        get_info=NONE,
    )
    connection = Connection(
        server,
        user=bind.bind_dn,
        password=bind.password,
        auto_bind=False,
        auto_referrals=False,
        receive_timeout=_RECEIVE_TIMEOUT,
        read_only=True,
        raise_exceptions=False,
    )
    try:
        if not connection.bind():
            raise DirectoryDiscoveryError(_result_message(connection, bind.password))
        if bind.start_tls and not bind.use_ssl and not connection.start_tls():
            raise DirectoryDiscoveryError(_result_message(connection, bind.password))
        entries: list[dict] = []
        truncated = False
        try:
            pages = connection.extend.standard.paged_search(
                search_base=bind.base_dn,
                search_filter=search_filter,
                search_scope=SUBTREE,
                attributes=list(_COMPUTER_ATTRIBUTES),
                paged_size=min(_PAGE_SIZE, limit),
                generator=True,
                size_limit=limit,
            )
            for item in pages:
                if item.get("type") != "searchResEntry":
                    continue
                entries.append({"dn": item.get("dn") or "", "attributes": item.get("attributes") or {}})
                if len(entries) >= limit:
                    truncated = True
                    break
        except LDAPException as exc:
            message = public_error(str(exc), bind.password)
            if _is_matching_rule_error(message):
                raise _MatchingRuleUnsupported(message) from exc
            if entries:
                return entries, True
            raise DirectoryDiscoveryError(message or "LDAP search failed") from exc
        description = str((connection.result or {}).get("description") or "")
        if description and description not in {"success", "sizeLimitExceeded", "timeLimitExceeded"}:
            message = _result_message(connection, bind.password)
            if _is_matching_rule_error(message):
                raise _MatchingRuleUnsupported(message)
            if not entries:
                raise DirectoryDiscoveryError(message)
            truncated = True
        elif description in {"sizeLimitExceeded", "timeLimitExceeded"}:
            truncated = True
        return entries, truncated
    finally:
        try:
            connection.unbind()
        except Exception:
            pass


def _result_message(connection, password: str) -> str:
    result = connection.result or {}
    description = str(result.get("description") or "ldap error")
    message = str(result.get("message") or "")
    text = description if not message else f"{description}: {message}"
    return public_error(text, password) or "LDAP request failed"


def _is_matching_rule_error(message: str) -> bool:
    lowered = message.casefold()
    return "inappropriatematching" in lowered or "unavailablecriticalextension" in lowered


def _lookup_host(
    computer: DirectoryComputer,
    index: dict[str, int],
    by_id: dict[int, KnownHost],
) -> KnownHost | None:
    keys: list[str] = []
    if computer.dns_hostname:
        keys.append(computer.dns_hostname.lower())
    if computer.cn:
        keys.append(computer.cn.lower())
    seen: set[str] = set()
    for key in keys:
        if key in seen:
            continue
        seen.add(key)
        host_id = index.get(key)
        if host_id is not None and host_id in by_id:
            return by_id[host_id]
    return None


def _plan_create(computer: DirectoryComputer, *, map_ou_to_site: bool) -> PlannedCreate | None:
    hostname = computer.dns_hostname or _clean_hostname(computer.cn)
    if hostname is None:
        return None
    os_type = os_type_from_operating_system(computer.operating_system)
    return PlannedCreate(
        name=computer.cn[:128],
        hostname=hostname,
        port=_SSH_PORT if os_type == "linux" else _WINRM_PORT,
        os_type=os_type,
        site=site_from_dn(computer.distinguished_name) if map_ou_to_site else None,
        is_active=not computer.disabled,
    )


def _plan_update(
    host: KnownHost,
    computer: DirectoryComputer,
    *,
    map_ou_to_site: bool,
) -> PlannedUpdate | None:
    name = computer.cn[:128] if host.name.startswith("discovered-") and computer.cn else None
    os_type = None
    if not (host.os_type or "").strip():
        os_type = os_type_from_operating_system(computer.operating_system)
    site = None
    if map_ou_to_site and not (host.site or "").strip():
        site = site_from_dn(computer.distinguished_name)
    if name is None and os_type is None and site is None:
        return None
    if host.id < 0:
        return None
    return PlannedUpdate(host_id=host.id, name=name, os_type=os_type, site=site)


def _split_dn(distinguished_name: str) -> list[str]:
    parts: list[str] = []
    current: list[str] = []
    escaped = False
    for char in distinguished_name:
        if escaped:
            current.append("\\")
            current.append(char)
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if char == ",":
            piece = "".join(current).strip()
            if piece:
                parts.append(piece)
            current = []
            continue
        current.append(char)
    if escaped:
        current.append("\\")
    tail = "".join(current).strip()
    if tail:
        parts.append(tail)
    return parts


def _unescape_dn_value(value: str) -> str:
    output: list[str] = []
    escaped = False
    for char in value.strip():
        if escaped:
            output.append(char)
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        output.append(char)
    return "".join(output).strip()


def _first_raw(attributes: dict, key: str):
    value = attributes.get(key)
    if isinstance(value, list):
        return value[0] if value else None
    return value


def _first_str(attributes: dict, key: str) -> str | None:
    value = _first_raw(attributes, key)
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _clean_hostname(value: str | None) -> str | None:
    if not value:
        return None
    text = value.strip().rstrip(".")
    if not text or len(text) > 256:
        return None
    if any(char.isspace() or ord(char) < 32 for char in text):
        return None
    return text


def _is_disabled(value) -> bool:
    if value is None or value == "":
        return False
    try:
        return bool(int(value) & _ACCOUNT_DISABLE)
    except (TypeError, ValueError):
        return False
