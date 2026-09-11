"""Resolve credentials linked to a host (primary + additional auth methods)."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from secaudit_core.models import Credential, Host


def linked_credentials(host: Host) -> list[Credential]:
    links = getattr(host, "credential_links", None)
    if links:
        ordered = sorted(links, key=lambda item: item.sort_order)
        return [link.credential for link in ordered if link.credential is not None]
    if host.credential is not None:
        return [host.credential]
    return []
