"""Read-only AD/LDAP computer discovery for the host inventory.

The directory is a source of computer names, not a second audit engine.
Existing nmap hosts are reused when the DNS name or short name already matches.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

MAX_COMPUTERS = 5000
DIRECTORY_IMPORT_LIMIT_MAX = 50000
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
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$"
)
_LINUX_MARKERS = (
    "linux",
    "ubuntu",
    "debian",
    "centos",
    "red hat",
    "rhel",
    "suse",
    "fedora",
    "astra",
    "alt linux",
    "altlinux",
    "red os",
    "redos",
    "rocky",
    "alma",
    "oracle",
)
_UNIX_MARKERS = (
    "freebsd",
    "openbsd",
    "netbsd",
    "dragonfly",
    "solaris",
    "illumos",
    "aix",
    "hp-ux",
    "unix",
    "macos",
    "darwin",
)


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
    search_filter: str | None = None
    extra_attributes: tuple[str, ...] = ()

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
    attributes: dict[str, str] = field(default_factory=dict)


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
    is_active: bool = True
    directory_managed: bool = False
    os_family: str | None = None
    os_version: str | None = None
    environment: str | None = None
    criticality: str | None = None


@dataclass
class PlannedCreate:
    name: str
    hostname: str
    port: int
    os_type: str
    site: str | None
    is_active: bool = True
    os_family: str | None = None
    os_version: str | None = None
    environment: str | None = None
    criticality: str | None = None


@dataclass
class PlannedUpdate:
    host_id: int
    name: str | None = None
    os_type: str | None = None
    site: str | None = None
    is_active: bool | None = None
    os_family: str | None = None
    os_version: str | None = None
    environment: str | None = None
    criticality: str | None = None


@dataclass
class PlannedLifecycle:
    host_id: int
    set_inactive: bool = False
    tag_stale: bool = False


@dataclass
class DirectoryImportPlan:
    creates: list[PlannedCreate] = field(default_factory=list)
    updates: list[PlannedUpdate] = field(default_factory=list)
    matched_ids: list[int] = field(default_factory=list)
    lifecycle: list[PlannedLifecycle] = field(default_factory=list)


DIRECTORY_MANAGED_TAG = "directory"
DIRECTORY_STALE_TAG = "stale"
MISSING_HOST_POLICIES = frozenset({"none", "inactive", "stale"})


def public_error(text: str, password: str) -> str:
    cleaned = text.replace("\x00", " ")
    if password:
        cleaned = cleaned.replace(password, "***")
    return " ".join(cleaned.split())[:500]


def computer_filter(enabled_only: bool) -> str:
    return _ENABLED_COMPUTER_FILTER if enabled_only else _COMPUTER_FILTER


_OU_REF = re.compile(r"^ou:(\d+)$", re.IGNORECASE)
_ATTR_RE = re.compile(r"^[A-Za-z][A-Za-z0-9-]{0,63}$")
_MAP_FIELDS = ("site", "environment", "criticality")
_CRITICALITY = frozenset({"low", "medium", "high", "critical"})


def validate_computer_filter(value: str | None) -> str | None:
    """Accept an operator LDAP filter. Empty means the built-in computer filter."""
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    if len(text) > 512 or any(ord(ch) < 32 for ch in text):
        raise ValueError("LDAP filter is invalid")
    if not (text.startswith("(") and text.endswith(")") and text.count("(") == text.count(")")):
        raise ValueError("LDAP filter must be a parenthesized filter")
    return text


def normalize_ou_field_map(raw: dict | None) -> dict[str, str]:
    """Keep site/environment/criticality mapped to ``ou:N`` or an LDAP attribute."""
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise ValueError("OU map must be an object")
    cleaned: dict[str, str] = {}
    for key in _MAP_FIELDS:
        if key not in raw or raw[key] is None:
            continue
        text = str(raw[key]).strip()
        if not text:
            continue
        match = _OU_REF.fullmatch(text)
        if match:
            index = int(match.group(1))
            if index < 1 or index > 16:
                raise ValueError("OU index must be between 1 and 16")
            cleaned[key] = f"ou:{index}"
            continue
        if not _ATTR_RE.fullmatch(text):
            raise ValueError("OU map values must be ou:N or an LDAP attribute name")
        cleaned[key] = text
    return cleaned


def mapped_attributes(field_map: dict[str, str]) -> tuple[str, ...]:
    return tuple(value for value in field_map.values() if not value.lower().startswith("ou:"))


def clamp_import_limit(limit: int | None, *, default: int = MAX_COMPUTERS) -> int:
    chosen = default if limit is None else limit
    return max(1, min(int(chosen), DIRECTORY_IMPORT_LIMIT_MAX))


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
    host = _normalize_directory_server(server)
    if port < 1 or port > 65535:
        raise ValueError("Directory port must be between 1 and 65535")
    if use_ssl and start_tls:
        raise ValueError("StartTLS is used on port 389; turn it off when LDAPS is enabled")
    base = _normalize_dn(base_dn, label="Base DN")
    bind = _normalize_dn(bind_dn, label="Bind DN")
    return host, port, base, bind, start_tls and not use_ssl


def _normalize_directory_server(server: str) -> str:
    """Accept a hostname, IPv4, or IPv6 (with optional ``[brackets]``)."""
    host = server.strip()
    if host.startswith("[") and host.endswith("]") and len(host) > 2:
        host = host[1:-1]
    if not host or len(host) > 253:
        raise ValueError("Directory server must be a hostname, IPv4, or IPv6 address")
    if "://" in host or "/" in host or " " in host:
        raise ValueError("Directory server must be a hostname, IPv4, or IPv6 address")
    try:
        addr = ipaddress.ip_address(host.split("%", 1)[0])
    except ValueError:
        if not _HOSTNAME_RE.fullmatch(host):
            raise ValueError("Directory server must be a hostname, IPv4, or IPv6 address")
        return host
    if addr.is_loopback or addr.is_unspecified or addr.is_multicast or addr.is_link_local:
        raise ValueError("Directory server address is not allowed")
    return str(addr)


def _normalize_dn(value: str, *, label: str) -> str:
    text = value.strip()
    if not text or len(text) > 512 or "=" not in text:
        raise ValueError(f"{label} must be an LDAP distinguished name")
    if any(ord(ch) < 32 for ch in text):
        raise ValueError(f"{label} contains unsupported characters")
    return text


def meaningful_ous(distinguished_name: str) -> list[str]:
    """OU names from the object outward, skipping the default AD containers."""
    names: list[str] = []
    for part in _split_dn(distinguished_name):
        if "=" not in part:
            continue
        key, raw = part.split("=", 1)
        if key.strip().casefold() != "ou":
            continue
        name = _unescape_dn_value(raw)
        if not name or name.casefold() in _SKIP_OUS:
            continue
        names.append(name[:64])
    return names


def site_from_dn(distinguished_name: str) -> str | None:
    """First meaningful OU, skipping the default AD containers."""
    names = meaningful_ous(distinguished_name)
    return names[0] if names else None


def os_identity_from_operating_system(value: str | None) -> tuple[str | None, str | None]:
    text = (value or "").strip()
    if not text:
        return None, None
    from secaudit_core.audit_flow_match import detect_family

    family = detect_family(text)
    match = re.search(r"\d+(?:\.\d+){0,3}", text)
    version = match.group(0)[:64] if match else None
    return (family[:32] if family else None), version


def host_fields_from_computer(
    computer: DirectoryComputer,
    field_map: dict[str, str],
    *,
    map_ou_to_site: bool,
) -> dict[str, str | None]:
    effective = dict(field_map)
    if map_ou_to_site and "site" not in effective:
        effective["site"] = "ou:1"
    ous = meaningful_ous(computer.distinguished_name)
    result: dict[str, str | None] = {"site": None, "environment": None, "criticality": None}
    for field_name, spec in effective.items():
        match = _OU_REF.fullmatch(spec)
        if match:
            index = int(match.group(1)) - 1
            value: str | None = ous[index] if 0 <= index < len(ous) else None
        else:
            value = computer.attributes.get(spec)
        if field_name == "criticality":
            folded = (value or "").strip().casefold()
            value = folded if folded in _CRITICALITY else None
        elif value:
            value = value.strip()[:64] or None
        result[field_name] = value
    return result


def os_type_from_operating_system(value: str | None) -> str:
    text = (value or "").casefold()
    if any(marker in text for marker in _LINUX_MARKERS):
        return "linux"
    if any(marker in text for marker in _UNIX_MARKERS):
        return "unix"
    return "windows"


def computer_from_attributes(
    attributes: dict,
    *,
    dn: str | None = None,
    extra_attributes: tuple[str, ...] = (),
) -> DirectoryComputer | None:
    cn = (_first_str(attributes, "cn") or "").strip()
    dns = _clean_hostname(_first_str(attributes, "dNSHostName"))
    if not cn and dns:
        cn = dns.split(".", 1)[0]
    hostname = dns or _clean_hostname(cn)
    if not cn or hostname is None:
        return None
    distinguished = _first_str(attributes, "distinguishedName") or (dn or "")
    extras: dict[str, str] = {}
    for name in extra_attributes:
        text = _first_str(attributes, name)
        if text:
            extras[name] = text[:64]
    return DirectoryComputer(
        cn=cn[:128],
        dns_hostname=dns,
        operating_system=_first_str(attributes, "operatingSystem"),
        distinguished_name=distinguished,
        disabled=_is_disabled(_first_raw(attributes, "userAccountControl")),
        attributes=extras,
    )


def plan_directory_import(
    computers: list[DirectoryComputer],
    known_hosts: list[KnownHost],
    *,
    aliases: dict[str, int] | None = None,
    map_ou_to_site: bool,
    missing_host_policy: str = "none",
    ou_field_map: dict[str, str] | None = None,
) -> DirectoryImportPlan:
    """Match directory computers to inventory hosts. Never touches another owner's rows."""
    policy = (missing_host_policy or "none").strip().lower()
    if policy not in MISSING_HOST_POLICIES:
        policy = "none"
    field_map = normalize_ou_field_map(ou_field_map)
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
    seen_ids: set[int] = set()
    for computer in computers:
        host = _lookup_host(computer, index, by_id)
        if host is None:
            if computer.disabled:
                continue
            created = _plan_create(computer, map_ou_to_site=map_ou_to_site, field_map=field_map)
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
                directory_managed=True,
            )
            remember(created.hostname, synthetic_id)
            remember(created.name, synthetic_id)
            if computer.dns_hostname:
                remember(computer.dns_hostname, synthetic_id)
            continue
        if host.id < 0:
            continue
        seen_ids.add(host.id)
        if computer.disabled:
            plan.matched_ids.append(host.id)
            if policy != "none":
                plan.lifecycle.append(
                    PlannedLifecycle(
                        host_id=host.id,
                        set_inactive=policy == "inactive",
                        tag_stale=policy == "stale",
                    )
                )
            continue
        update = _plan_update(host, computer, map_ou_to_site=map_ou_to_site, field_map=field_map)
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
            if update.os_family is not None:
                host.os_family = update.os_family
            if update.os_version is not None:
                host.os_version = update.os_version
            if update.environment is not None:
                host.environment = update.environment
            if update.criticality is not None:
                host.criticality = update.criticality
            if update.is_active is not None:
                host.is_active = update.is_active
            remember(host.name, host.id)
            remember(host.hostname, host.id)
    if policy != "none":
        for host in known_hosts:
            if host.id < 0 or not host.directory_managed or host.id in seen_ids:
                continue
            plan.lifecycle.append(
                PlannedLifecycle(
                    host_id=host.id,
                    set_inactive=policy == "inactive",
                    tag_stale=policy == "stale",
                )
            )
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


def search_computers(bind: DirectoryBind, *, limit: int | None = None) -> DirectorySearchResult:
    limit = clamp_import_limit(limit)
    search_filter = bind.search_filter or computer_filter(bind.enabled_only)
    try:
        raw, truncated = _ldap_search(bind, search_filter, limit)
    except _MatchingRuleUnsupported:
        if bind.search_filter or not bind.enabled_only:
            raise
        raw, truncated = _ldap_search(bind, computer_filter(False), limit)
    computers: list[DirectoryComputer] = []
    for item in raw:
        computer = computer_from_attributes(
            item["attributes"],
            dn=item.get("dn"),
            extra_attributes=bind.extra_attributes,
        )
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
                attributes=list(_COMPUTER_ATTRIBUTES) + [
                    name for name in bind.extra_attributes if name not in _COMPUTER_ATTRIBUTES
                ],
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


def _plan_create(
    computer: DirectoryComputer,
    *,
    map_ou_to_site: bool,
    field_map: dict[str, str],
) -> PlannedCreate | None:
    hostname = computer.dns_hostname or _clean_hostname(computer.cn)
    if hostname is None:
        return None
    os_type = os_type_from_operating_system(computer.operating_system)
    family, version = os_identity_from_operating_system(computer.operating_system)
    fields = host_fields_from_computer(computer, field_map, map_ou_to_site=map_ou_to_site)
    return PlannedCreate(
        name=computer.cn[:128],
        hostname=hostname,
        port=_SSH_PORT if os_type in {"linux", "unix"} else _WINRM_PORT,
        os_type=os_type,
        site=fields["site"],
        is_active=not computer.disabled,
        os_family=family,
        os_version=version,
        environment=fields["environment"],
        criticality=fields["criticality"],
    )


def _empty(value: str | None) -> bool:
    return not (value or "").strip()


def _plan_update(
    host: KnownHost,
    computer: DirectoryComputer,
    *,
    map_ou_to_site: bool,
    field_map: dict[str, str],
) -> PlannedUpdate | None:
    name = computer.cn[:128] if host.name.startswith("discovered-") and computer.cn else None
    os_type = os_type_from_operating_system(computer.operating_system) if _empty(host.os_type) else None
    family, version = os_identity_from_operating_system(computer.operating_system)
    if not _empty(host.os_family):
        family = None
    if not _empty(host.os_version):
        version = None
    fields = host_fields_from_computer(computer, field_map, map_ou_to_site=map_ou_to_site)
    site = fields["site"] if _empty(host.site) else None
    environment = fields["environment"] if _empty(host.environment) else None
    criticality = fields["criticality"] if _empty(host.criticality) else None
    is_active = True if not host.is_active else None
    if (
        name is None
        and os_type is None
        and site is None
        and is_active is None
        and family is None
        and version is None
        and environment is None
        and criticality is None
    ):
        return None
    if host.id < 0:
        return None
    return PlannedUpdate(
        host_id=host.id,
        name=name,
        os_type=os_type,
        site=site,
        is_active=is_active,
        os_family=family,
        os_version=version,
        environment=environment,
        criticality=criticality,
    )


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
