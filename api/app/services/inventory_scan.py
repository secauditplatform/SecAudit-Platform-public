"""Inventory scan validation re-exports and async DB helpers (API only)."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models import InventoryScan
from secaudit_core.inventory_scan import (  # noqa: F401 — re-exported for API callers
    DiscoveredHost,
    HostPortInfo,
    decode_nmap_flags,
    encode_nmap_flags,
    format_nmap_flags_display,
    parse_nmap_discovery_xml,
    parse_nmap_port_scan_xml,
    validate_nmap_flags,
    validate_scan_target,
)

__all__ = [
    "DiscoveredHost",
    "HostPortInfo",
    "decode_nmap_flags",
    "encode_nmap_flags",
    "format_nmap_flags_display",
    "get_scan_detail",
    "parse_nmap_discovery_xml",
    "parse_nmap_port_scan_xml",
    "validate_nmap_flags",
    "validate_scan_target",
]


async def get_scan_detail(db: AsyncSession, scan_id: int) -> InventoryScan | None:
    result = await db.execute(
        select(InventoryScan)
        .options(selectinload(InventoryScan.results))
        .where(InventoryScan.id == scan_id)
    )
    return result.scalar_one_or_none()
