"""Classify hosts in a completed job run for partial restart."""

from __future__ import annotations

from collections import defaultdict
from typing import Iterable, Literal

from secaudit_core.enums import CheckStatus

SubsetKind = Literal["failed", "skipped", "selected", "all"]


def classify_host_outcomes(
    checks: Iterable[object],
) -> dict[str, list[int]]:
    """Group host ids by outcome from check results.

    failed — any FAIL or ERROR on the host
    skipped — no FAIL/ERROR, at least one SKIP
    all — every host that produced at least one check result
    """
    by_host: dict[int, set[str]] = defaultdict(set)
    for check in checks:
        host_id = getattr(check, "host_id", None)
        status = getattr(check, "status", None)
        if host_id is None or status is None:
            continue
        value = status.value if isinstance(status, CheckStatus) else str(status)
        by_host[int(host_id)].add(value.lower())

    failed: list[int] = []
    skipped: list[int] = []
    all_hosts = sorted(by_host)
    for host_id in all_hosts:
        statuses = by_host[host_id]
        if CheckStatus.FAIL.value in statuses or CheckStatus.ERROR.value in statuses:
            failed.append(host_id)
        elif CheckStatus.SKIP.value in statuses:
            skipped.append(host_id)
    return {"failed": failed, "skipped": skipped, "all": all_hosts}


def resolve_subset_host_ids(
    *,
    subset: SubsetKind,
    classified: dict[str, list[int]],
    selected_host_ids: list[int] | None = None,
    allowed_host_ids: Iterable[int] | None = None,
) -> list[int]:
    """Pick host ids for a restart. Raises ValueError on empty/invalid selection."""
    allowed = set(allowed_host_ids) if allowed_host_ids is not None else set(classified["all"])
    if subset == "all":
        chosen = [host_id for host_id in classified["all"] if host_id in allowed] or sorted(allowed)
    elif subset == "failed":
        chosen = [host_id for host_id in classified["failed"] if host_id in allowed]
    elif subset == "skipped":
        chosen = [host_id for host_id in classified["skipped"] if host_id in allowed]
    elif subset == "selected":
        if not selected_host_ids:
            raise ValueError("host_ids required when subset is selected")
        chosen = sorted({int(host_id) for host_id in selected_host_ids})
        unknown = [host_id for host_id in chosen if host_id not in allowed]
        if unknown:
            raise ValueError(f"Hosts not in source run: {unknown}")
    else:
        raise ValueError(f"Unsupported subset: {subset}")

    if not chosen:
        raise ValueError(f"No hosts match subset '{subset}'")
    return chosen
