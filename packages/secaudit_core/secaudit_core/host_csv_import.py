"""Plan a host inventory import from CSV.

Matching follows directory import: a row hits an existing host when its hostname
or IP equals that host's name, hostname, or an nmap resolved-name alias. The
planner never stores passwords or keys and never starts a scan.
"""

from __future__ import annotations

import csv
import io
import ipaddress
import re
from dataclasses import dataclass, replace

MAX_CSV_BYTES = 1_000_000
MAX_DATA_ROWS = 2000
_MAX_NAME = 128
_MAX_HOSTNAME = 256
_MAX_LABEL = 64
_MAX_TAGS = 32

_HOST_LABEL = re.compile(r"^[A-Za-z0-9._:-]{1,256}$")
_SECRET_HEADERS = frozenset(
    {
        "password",
        "passwd",
        "passphrase",
        "secret",
        "token",
        "private_key",
        "privatekey",
        "ssh_key",
        "sshkey",
        "credential",
        "credentials",
        "bind_password",
        "api_key",
        "access_key",
    }
)
_COLUMNS = {
    "hostname": "hostname",
    "host": "hostname",
    "fqdn": "hostname",
    "dns": "hostname",
    "dns_hostname": "hostname",
    "ip": "ip",
    "ip_address": "ip",
    "address": "ip",
    "name": "name",
    "display_name": "name",
    "tags": "tags",
    "tag": "tags",
    "site": "site",
    "environment": "environment",
    "env": "environment",
    "criticality": "criticality",
    "os_type": "os_type",
    "os": "os_type",
    "port": "port",
}
_CRITICALITY = {
    "low": "low",
    "низкая": "low",
    "medium": "medium",
    "средняя": "medium",
    "high": "high",
    "высокая": "high",
    "critical": "critical",
    "критичная": "critical",
    "критическая": "critical",
}


class CsvImportError(ValueError):
    """The whole file cannot be imported."""


@dataclass
class CsvHostRecord:
    id: int
    name: str
    hostname: str
    port: int = 22
    os_type: str | None = None
    site: str | None = None
    environment: str | None = None
    criticality: str | None = None
    tags: tuple[str, ...] = ()


@dataclass
class RejectedCsvRow:
    row: int
    reason: str


@dataclass
class PlannedCsvCreate:
    name: str
    hostname: str
    port: int
    os_type: str | None
    site: str | None
    environment: str | None
    criticality: str | None
    tags: tuple[str, ...]


@dataclass
class PlannedCsvUpdate:
    host_id: int
    name: str | None = None
    hostname: str | None = None
    port: int | None = None
    os_type: str | None = None
    site: str | None = None
    environment: str | None = None
    criticality: str | None = None
    tags: tuple[str, ...] | None = None


@dataclass
class CsvImportPlan:
    creates: list[PlannedCsvCreate]
    updates: list[PlannedCsvUpdate]
    unchanged: int
    rejected: list[RejectedCsvRow]
    truncated: bool = False


@dataclass
class _RowValues:
    display: str | None
    address: str | None
    connection: str
    port: int | None
    os_type: str | None
    site: str | None
    environment: str | None
    criticality: str | None
    tags: tuple[str, ...]
    keys: list[str]


def plan_host_csv(
    payload: str | bytes,
    known: list[CsvHostRecord],
    *,
    aliases: dict[str, int] | None = None,
) -> CsvImportPlan:
    """Return creates, updates, and rejected rows. A bad row does not fail the file."""
    text = _decode(payload)
    delimiter = ";" if _header_line(text).count(";") > _header_line(text).count(",") else ","
    rows = list(csv.reader(io.StringIO(text), delimiter=delimiter))
    if not rows or not any(cell.strip() for cell in rows[0]):
        raise CsvImportError("CSV is empty")

    columns = _map_headers(rows[0])
    if "hostname" not in columns and "ip" not in columns:
        raise CsvImportError("CSV needs a hostname or IP column")

    data = rows[1:]
    truncated = len(data) > MAX_DATA_ROWS
    if truncated:
        data = data[:MAX_DATA_ROWS]

    by_id: dict[int, CsvHostRecord] = {}
    original: dict[int, CsvHostRecord] = {}
    index: dict[str, int] = {}
    for host in known:
        if host.id <= 0:
            continue
        original[host.id] = replace(host)
        by_id[host.id] = replace(host)
        _remember(index, host.hostname, host.id)
        _remember(index, host.name, host.id)
    for alias, host_id in (aliases or {}).items():
        if host_id in by_id:
            _remember(index, alias, host_id)

    created: list[CsvHostRecord] = []
    rejected: list[RejectedCsvRow] = []
    unchanged = 0

    for offset, cells in enumerate(data, start=2):
        if not any(cell.strip() for cell in cells):
            continue
        if any(_cell_has_secret(cell) for cell in cells):
            rejected.append(RejectedCsvRow(offset, "secret_material"))
            continue
        parsed = _parse_row(cells, columns)
        if isinstance(parsed, str):
            rejected.append(RejectedCsvRow(offset, parsed))
            continue
        match = _lookup(parsed.keys, index, by_id)
        if match == "ambiguous":
            rejected.append(RejectedCsvRow(offset, "ambiguous"))
            continue
        if match is None:
            record = _record_from_row(parsed, host_id=-(len(created) + 1))
            created.append(record)
            by_id[record.id] = record
            _remember(index, record.hostname, record.id)
            _remember(index, record.name, record.id)
            for key in parsed.keys:
                _remember(index, key, record.id)
            continue
        if _address_conflicts(match, parsed.address):
            rejected.append(RejectedCsvRow(offset, "ambiguous"))
            continue
        changed = _apply_row(match, parsed)
        if match.id > 0 and changed:
            continue
        unchanged += 1

    creates = [
        PlannedCsvCreate(
            name=record.name,
            hostname=record.hostname,
            port=record.port,
            os_type=record.os_type,
            site=record.site,
            environment=record.environment,
            criticality=record.criticality,
            tags=record.tags,
        )
        for record in created
    ]
    updates: list[PlannedCsvUpdate] = []
    for host_id, before in original.items():
        after = by_id[host_id]
        diff = _diff(before, after)
        if diff is not None:
            updates.append(diff)
    return CsvImportPlan(
        creates=creates,
        updates=updates,
        unchanged=unchanged,
        rejected=rejected,
        truncated=truncated,
    )


def _decode(payload: str | bytes) -> str:
    if isinstance(payload, bytes):
        if len(payload) > MAX_CSV_BYTES:
            raise CsvImportError("CSV is too large")
        try:
            text = payload.decode("utf-8-sig")
        except UnicodeDecodeError as exc:
            raise CsvImportError("CSV must be UTF-8") from exc
    else:
        text = payload
    if "\x00" in text or not text.strip():
        raise CsvImportError("CSV is empty" if not text.strip() else "CSV must be UTF-8")
    return text


def _header_line(text: str) -> str:
    return text.splitlines()[0] if text else ""


def _header_key(value: str) -> str:
    return re.sub(r"[\s\-]+", "_", value.strip().casefold())


def _is_secret_header(key: str) -> bool:
    if key in _SECRET_HEADERS:
        return True
    return (
        key.endswith("_password")
        or key.endswith("_secret")
        or key.endswith("_token")
        or "private_key" in key
    )


def _map_headers(header: list[str]) -> dict[str, int]:
    columns: dict[str, int] = {}
    for index, cell in enumerate(header):
        key = _header_key(cell)
        if not key:
            continue
        if _is_secret_header(key):
            raise CsvImportError("CSV must not include passwords or keys")
        field = _COLUMNS.get(key)
        if field and field not in columns:
            columns[field] = index
    return columns


def _cell(cells: list[str], columns: dict[str, int], field: str) -> str:
    index = columns.get(field)
    if index is None or index >= len(cells):
        return ""
    return cells[index].strip()


def _cell_has_secret(value: str) -> bool:
    text = value.casefold()
    return "-----begin " in text and "private key" in text


def _is_ip(value: str | None) -> bool:
    if not value:
        return False
    try:
        ipaddress.ip_address(value.strip())
    except ValueError:
        return False
    return True


def _remember(index: dict[str, int], key: str | None, host_id: int) -> None:
    if not key:
        return
    lowered = key.strip().lower()
    if lowered and lowered not in index:
        index[lowered] = host_id


def _lookup(keys: list[str], index: dict[str, int], by_id: dict[int, CsvHostRecord]) -> CsvHostRecord | str | None:
    found: list[int] = []
    for key in keys:
        host_id = index.get(key)
        if host_id is not None and host_id not in found:
            found.append(host_id)
    if len(found) > 1:
        return "ambiguous"
    if not found:
        return None
    return by_id.get(found[0])


def _parse_row(cells: list[str], columns: dict[str, int]) -> _RowValues | str:
    hostname = _cell(cells, columns, "hostname")
    ip_text = _cell(cells, columns, "ip")
    name = _cell(cells, columns, "name")
    if not hostname and not ip_text and not name:
        return "missing_identity"
    if ip_text and not _is_ip(ip_text):
        return "invalid_ip"
    if hostname and not _is_ip(hostname) and not _HOST_LABEL.match(hostname):
        return "invalid_hostname"
    if name and (len(name) > _MAX_NAME or any(ord(ch) < 32 for ch in name)):
        return "field_too_long"

    address = ip_text or (hostname if _is_ip(hostname) else None)
    label = name or (hostname if hostname and not _is_ip(hostname) else None)
    connection = address or hostname or label
    if connection is None:
        return "missing_identity"
    display = label or connection
    if len(display) > _MAX_NAME or len(connection) > _MAX_HOSTNAME:
        return "field_too_long"

    port_text = _cell(cells, columns, "port")
    port: int | None = None
    if port_text:
        if not port_text.isdigit():
            return "invalid_port"
        port = int(port_text)
        if port < 1 or port > 65535:
            return "invalid_port"

    criticality_text = _cell(cells, columns, "criticality")
    criticality: str | None = None
    if criticality_text:
        criticality = _CRITICALITY.get(criticality_text.casefold())
        if criticality is None:
            return "invalid_criticality"

    try:
        site = _limit(_cell(cells, columns, "site"))
        environment = _limit(_cell(cells, columns, "environment"))
        os_type = _limit(_cell(cells, columns, "os_type"))
        tags = _tags(_cell(cells, columns, "tags"))
    except _FieldTooLong:
        return "field_too_long"

    keys: list[str] = []
    for raw in (address, hostname, label, name):
        if not raw:
            continue
        lowered = raw.strip().lower()
        if lowered and lowered not in keys:
            keys.append(lowered)
    return _RowValues(
        display=display,
        address=address,
        connection=connection,
        port=port,
        os_type=os_type,
        site=site,
        environment=environment,
        criticality=criticality,
        tags=tags,
        keys=keys,
    )


class _FieldTooLong(Exception):
    pass


def _limit(value: str) -> str | None:
    if not value:
        return None
    if len(value) > _MAX_LABEL:
        raise _FieldTooLong
    return value


def _tags(value: str) -> tuple[str, ...]:
    if not value:
        return ()
    seen: set[str] = set()
    tags: list[str] = []
    for part in re.split(r"[,;|]", value):
        name = part.strip()
        if not name:
            continue
        if len(name) > _MAX_LABEL:
            raise _FieldTooLong
        folded = name.casefold()
        if folded in seen:
            continue
        seen.add(folded)
        tags.append(name)
        if len(tags) > _MAX_TAGS:
            raise _FieldTooLong
    return tuple(tags)


def _record_from_row(parsed: _RowValues, *, host_id: int) -> CsvHostRecord:
    return CsvHostRecord(
        id=host_id,
        name=parsed.display or parsed.connection,
        hostname=parsed.connection,
        port=parsed.port or 22,
        os_type=parsed.os_type,
        site=parsed.site,
        environment=parsed.environment,
        criticality=parsed.criticality,
        tags=parsed.tags,
    )


def _address_conflicts(host: CsvHostRecord, address: str | None) -> bool:
    if not address or not _is_ip(host.hostname):
        return False
    return host.hostname.strip().lower() != address.strip().lower()


def _apply_row(host: CsvHostRecord, parsed: _RowValues) -> bool:
    changed = False
    if parsed.display and parsed.display != host.name and not (_is_ip(parsed.display) and not _is_ip(host.name)):
        host.name = parsed.display
        changed = True
    if parsed.address and parsed.address != host.hostname and not _address_conflicts(host, parsed.address):
        host.hostname = parsed.address
        changed = True
    if parsed.port is not None and parsed.port != host.port:
        host.port = parsed.port
        changed = True
    for field in ("os_type", "site", "environment", "criticality"):
        value = getattr(parsed, field)
        if value and value != getattr(host, field):
            setattr(host, field, value)
            changed = True
    if parsed.tags:
        merged = _union_tags(host.tags, parsed.tags)
        if merged != host.tags:
            host.tags = merged
            changed = True
    return changed


def _union_tags(existing: tuple[str, ...], extra: tuple[str, ...]) -> tuple[str, ...]:
    seen = {tag.casefold() for tag in existing}
    merged = list(existing)
    for tag in extra:
        if tag.casefold() in seen:
            continue
        seen.add(tag.casefold())
        merged.append(tag)
    return tuple(merged)


def _diff(before: CsvHostRecord, after: CsvHostRecord) -> PlannedCsvUpdate | None:
    name = after.name if after.name != before.name else None
    hostname = after.hostname if after.hostname != before.hostname else None
    port = after.port if after.port != before.port else None
    os_type = after.os_type if after.os_type != before.os_type else None
    site = after.site if after.site != before.site else None
    environment = after.environment if after.environment != before.environment else None
    criticality = after.criticality if after.criticality != before.criticality else None
    tags = after.tags if after.tags != before.tags else None
    if all(
        value is None
        for value in (name, hostname, port, os_type, site, environment, criticality, tags)
    ):
        return None
    return PlannedCsvUpdate(
        host_id=before.id,
        name=name,
        hostname=hostname,
        port=port,
        os_type=os_type,
        site=site,
        environment=environment,
        criticality=criticality,
        tags=tags,
    )
