"""Serialize AuditFlow runs for the wizard and pick hosts to re-probe."""

from secaudit_core.audit_flow_match import display_os_guess


def job_run_ids_for_host(row) -> list[int]:
    ids: list[int] = []
    if getattr(row, "job_run_id", None):
        ids.append(row.job_run_id)
    for item in getattr(row, "extra_runs_json", None) or []:
        job_run_id = item.get("job_run_id")
        if job_run_id:
            ids.append(int(job_run_id))
    return ids


def summary_payload(job_run_id: int | None, summaries: dict[int, dict] | None) -> dict | None:
    if not job_run_id or not summaries:
        return None
    return summaries.get(int(job_run_id))


def host_to_read(
    row,
    *,
    summaries: dict[int, dict] | None = None,
    reused_host_ids: set[int] | None = None,
) -> dict:
    ports = []
    open_ports = getattr(row, "open_ports", None)
    if open_ports:
        ports = [int(p) for p in str(open_ports).split(",") if p.strip().isdigit()]
    extra_checks = []
    for item in getattr(row, "extra_runs_json", None) or []:
        job_run_id = item.get("job_run_id")
        summary = summary_payload(job_run_id, summaries) or {}
        extra_checks.append(
            {
                **summary,
                "profile_id": item.get("profile_id"),
                "profile_name": item.get("profile_name") or item.get("profile_label") or summary.get("profile_name") or summary.get("profile_label"),
                "job_run_id": job_run_id,
            }
        )
    host_id = getattr(row, "ephemeral_host_id", None)
    inventory_reused = bool(host_id and reused_host_ids and host_id in reused_host_ids)
    credential = getattr(row, "credential", None)
    return {
        "id": row.id,
        "ip_address": row.ip_address,
        "hostname": row.hostname,
        "platform": row.platform,
        "os_guess": display_os_guess(row.os_guess),
        "open_ports": ports,
        "credential_id": row.credential_id,
        "credential_label": credential.label if credential else None,
        "profile_id": row.profile_id,
        "profile_name": row.profile_name,
        "confidence": row.confidence,
        "alternatives": row.alternatives_json or [],
        "extra_profiles": row.extra_profiles_json or [],
        "extra_checks": extra_checks,
        "check_summary": summary_payload(row.job_run_id, summaries),
        "selected": row.selected,
        "skip_reason": row.skip_reason,
        "skip_detail": row.skip_detail,
        "job_run_id": row.job_run_id,
        "ephemeral_host_id": host_id,
        "inventory_reused": inventory_reused,
        "ssh_host_key_fingerprint": getattr(row, "ssh_host_key_fingerprint", None),
    }


def run_to_read(
    run,
    *,
    summaries: dict[int, dict] | None = None,
    reused_host_ids: set[int] | None = None,
) -> dict:
    return {
        "id": run.id,
        "status": run.status.value if hasattr(run.status, "value") else run.status,
        "targets": run.targets_json or [],
        "error_message": run.error_message,
        "hosts_found": run.hosts_found,
        "save_to_inventory": bool(getattr(run, "save_to_inventory", False)),
        "started_at": run.started_at,
        "finished_at": run.finished_at,
        "created_at": run.created_at,
        "hosts": [
            host_to_read(h, summaries=summaries, reused_host_ids=reused_host_ids)
            for h in sorted(run.hosts or [], key=lambda row: row.id)
        ],
        "credentials": [
            {
                "id": cred.id,
                "label": cred.label,
                "credential_type": (
                    cred.credential_type.value
                    if hasattr(cred.credential_type, "value")
                    else cred.credential_type
                ),
                "username": cred.username,
                "service_username": cred.service_username,
                "has_service_secret": bool(getattr(cred, "encrypted_service_secret", None)),
            }
            for cred in (run.credentials or [])
        ],
    }


def reprobe_target_ids(run, *, host_ids: list[int] | None = None) -> list[int]:
    wanted = set(host_ids) if host_ids is not None else None
    return [
        row.id
        for row in (run.hosts or [])
        if not row.job_run_id
        and (
            (wanted is not None and row.id in wanted)
            or (
                wanted is None
                and (
                    row.skip_reason in {"auth_failed", "unreachable", "checking"}
                    or not row.credential_id
                )
            )
        )
    ]
