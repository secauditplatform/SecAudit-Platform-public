"""Read-only SNMP GET of sysDescr, sysObjectID and sysName.

One response per address. No SET, no trap receiver, no vendor MIB walk.
"""

from __future__ import annotations

import asyncio
import ipaddress
from dataclasses import dataclass

from pysnmp.hlapi.v3arch.asyncio import (
    CommunityData,
    ContextData,
    ObjectIdentity,
    ObjectType,
    SnmpEngine,
    Udp6TransportTarget,
    UdpTransportTarget,
    UsmUserData,
    get_cmd,
    usmAesCfb128Protocol,
    usmAesCfb192Protocol,
    usmAesCfb256Protocol,
    usmDESPrivProtocol,
    usmHMAC128SHA224AuthProtocol,
    usmHMAC192SHA256AuthProtocol,
    usmHMAC256SHA384AuthProtocol,
    usmHMAC384SHA512AuthProtocol,
    usmHMACMD5AuthProtocol,
    usmHMACSHAAuthProtocol,
    usmNoPrivProtocol,
)

from secaudit_core.inventory_scan import ScanCancelledError
from secaudit_core.snmp_discovery import SNMP_OIDS

_AUTH = {
    "MD5": usmHMACMD5AuthProtocol,
    "SHA": usmHMACSHAAuthProtocol,
    "SHA224": usmHMAC128SHA224AuthProtocol,
    "SHA256": usmHMAC192SHA256AuthProtocol,
    "SHA384": usmHMAC256SHA384AuthProtocol,
    "SHA512": usmHMAC384SHA512AuthProtocol,
}
_PRIV = {
    "DES": usmDESPrivProtocol,
    "AES": usmAesCfb128Protocol,
    "AES192": usmAesCfb192Protocol,
    "AES256": usmAesCfb256Protocol,
}

_CONCURRENCY = 32
_TIMEOUT_SECONDS = 1.0


@dataclass(frozen=True)
class SnmpIdentity:
    ip: str
    sys_name: str | None
    sys_descr: str | None
    sys_object_id: str | None


@dataclass
class SnmpProbeReport:
    hits: list[SnmpIdentity]
    timeouts: int = 0
    rejected: int = 0


def probe_snmp_addresses(
    addresses: list[str],
    *,
    version: str,
    port: int,
    community: str | None = None,
    username: str | None = None,
    auth_protocol: str | None = None,
    auth_key: str | None = None,
    priv_protocol: str | None = None,
    priv_key: str | None = None,
    cancelled=None,
) -> SnmpProbeReport:
    """Probe addresses. A silent host is a miss, not a failed scan."""
    return asyncio.run(
        _probe_all(
            addresses,
            version=version,
            port=port,
            community=community,
            username=username,
            auth_protocol=auth_protocol,
            auth_key=auth_key,
            priv_protocol=priv_protocol,
            priv_key=priv_key,
            cancelled=cancelled,
        )
    )


async def _probe_all(
    addresses: list[str],
    *,
    version: str,
    port: int,
    community: str | None,
    username: str | None,
    auth_protocol: str | None,
    auth_key: str | None,
    priv_protocol: str | None,
    priv_key: str | None,
    cancelled,
) -> SnmpProbeReport:
    report = SnmpProbeReport(hits=[])
    semaphore = asyncio.Semaphore(_CONCURRENCY)

    async def one(ip: str) -> None:
        if cancelled and cancelled():
            raise ScanCancelledError()
        async with semaphore:
            if cancelled and cancelled():
                raise ScanCancelledError()
            outcome, identity = await _probe_one(
                ip,
                version=version,
                port=port,
                community=community,
                username=username,
                auth_protocol=auth_protocol,
                auth_key=auth_key,
                priv_protocol=priv_protocol,
                priv_key=priv_key,
            )
        if outcome == "ok" and identity is not None:
            report.hits.append(identity)
        elif outcome == "rejected":
            report.rejected += 1
        else:
            report.timeouts += 1

    await asyncio.gather(*(one(ip) for ip in addresses))
    return report


async def _probe_one(
    ip: str,
    *,
    version: str,
    port: int,
    community: str | None,
    username: str | None,
    auth_protocol: str | None,
    auth_key: str | None,
    priv_protocol: str | None,
    priv_key: str | None,
) -> tuple[str, SnmpIdentity | None]:
    engine = SnmpEngine()
    try:
        target = await _target(ip, port)
        auth = _auth_data(
            version,
            community=community,
            username=username,
            auth_protocol=auth_protocol,
            auth_key=auth_key,
            priv_protocol=priv_protocol,
            priv_key=priv_key,
        )
        error_indication, error_status, _error_index, var_binds = await get_cmd(
            engine,
            auth,
            target,
            ContextData(),
            *[ObjectType(ObjectIdentity(oid)) for oid in SNMP_OIDS],
        )
    except ScanCancelledError:
        raise
    except Exception:
        return "timeout", None
    finally:
        engine.close_dispatcher()

    if error_indication:
        text = str(error_indication).lower()
        if any(word in text for word in ("auth", "decrypt", "unknown user", "wrong digest")):
            return "rejected", None
        return "timeout", None
    if error_status:
        status = str(error_status).lower()
        if "auth" in status:
            return "rejected", None
        return "timeout", None

    values = [_text_of(bind) for bind in var_binds]
    descr, object_id, name = (values + ["", "", ""])[:3]
    if not any((descr, object_id, name)):
        return "timeout", None
    return (
        "ok",
        SnmpIdentity(
            ip=ip,
            sys_name=name or None,
            sys_descr=descr or None,
            sys_object_id=object_id or None,
        ),
    )


async def _target(ip: str, port: int):
    address = (ip, port)
    if ipaddress.ip_address(ip).version == 6:
        return await Udp6TransportTarget.create(address, timeout=_TIMEOUT_SECONDS, retries=0)
    return await UdpTransportTarget.create(address, timeout=_TIMEOUT_SECONDS, retries=0)


def _auth_data(
    version: str,
    *,
    community: str | None,
    username: str | None,
    auth_protocol: str | None,
    auth_key: str | None,
    priv_protocol: str | None,
    priv_key: str | None,
):
    if version == "v2c":
        return CommunityData(community or "", mpModel=1)
    auth_proto = _AUTH[(auth_protocol or "SHA256").upper()]
    if priv_key and priv_protocol:
        priv_proto = _PRIV[priv_protocol.upper()]
        return UsmUserData(
            username or "",
            auth_key or "",
            priv_key,
            authProtocol=auth_proto,
            privProtocol=priv_proto,
        )
    return UsmUserData(
        username or "",
        auth_key or "",
        authProtocol=auth_proto,
        privProtocol=usmNoPrivProtocol,
    )


def _text_of(bind) -> str:
    value = bind[1]
    text = value.prettyPrint() if hasattr(value, "prettyPrint") else str(value)
    cleaned = " ".join(text.split())
    if not cleaned or cleaned.lower() in {"nosuchobject", "nosuchinstance", "endofmibview"}:
        return ""
    return cleaned[:512]
