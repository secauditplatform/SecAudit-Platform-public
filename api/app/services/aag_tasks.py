"""Queue an AAG task without touching compliance runs.

The outbox callback kind is ``aag_artifact``. That name is absent from the
job and remediation failure map, so a model error cannot mark a run failed.
Only the artifact id is placed on the queue. The API key stays in the
provider row and is decrypted by the worker.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlparse

from fastapi import HTTPException, Request
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.auth import AuthUser
from app.core.config import settings
from app.models import (
    AagArtifact,
    AagCallLog,
    AagProviderConfig,
    CheckResult,
    Host,
    Job,
    JobRun,
    JobStatus,
    Profile,
)
from app.pagination import paginate_scalars
from app.schemas import AagExplainCandidate, AagPackageDraft, AagTaskCreate
from app.services.audit_log import log_audit_event
from app.services.dispatch import commit_and_try_dispatch, enqueue_run_dispatch
from app.services.object_rbac import applies_engineer_scope, assert_can_access, rbac_enabled
from app.services.profiles import ProfileService
from secaudit_core.aag_client import (
    MAX_FINDINGS,
    build_explain_fragment,
    citation_payload,
    generated_package_files,
    input_hash,
    normalize_package_files,
    official_benchmark_name,
    package_request_errors,
    redact_fragment,
    write_generated_package,
)
from secaudit_core.enums import OutboxStatus
from secaudit_core.profile_packages import (
    discover_remediation_scripts,
    load_profile_rules_metadata,
    rule_identity_keys,
)
from secaudit_core.url_safety import UnsafeOutboundURLError, validate_outbound_webhook_url

AAG_TASK_NAME = "app.tasks.aag.run_aag_task"
AAG_QUEUE = "aag"
AAG_CALLBACK_KIND = "aag_artifact"


def contour_switch(*, saved: bool | None, env_enabled: bool) -> bool:
    """Connection-screen switch. The env flag applies only before the first save."""
    if saved is None:
        return bool(env_enabled)
    return bool(saved)


def task_submission_block(
    *,
    ai_enabled: bool,
    provider: str | None,
    last_test_ok: bool | None,
    demo_mode: bool,
) -> None:
    """Refuse a task before any customer text is queued."""
    if not ai_enabled or provider in (None, "", "none"):
        raise HTTPException(status_code=403, detail="AAG is disabled")
    if provider == "external" and demo_mode:
        raise HTTPException(status_code=403, detail="External AI API is disabled in demo mode")
    if last_test_ok is False:
        raise HTTPException(status_code=503, detail="Provider does not respond")
    if provider not in ("internal", "external"):
        raise HTTPException(status_code=403, detail="AAG is disabled")


def _active_base_url(row: AagProviderConfig) -> str:
    base_url = row.external_base_url if row.provider == "external" else row.internal_base_url
    if not (base_url or "").strip():
        raise HTTPException(status_code=422, detail="Provider address is not configured")
    try:
        return validate_outbound_webhook_url(
            base_url or "",
            allow_http=row.provider == "internal",
            allow_private=True if row.provider == "internal" else settings.outbound_webhooks_allow_private,
        )
    except UnsafeOutboundURLError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


async def assert_cited_run_visible(db: AsyncSession, user: AuthUser, run_id: int | None) -> None:
    """Same owner check as a job run. No access means no artifact row."""
    if run_id is None:
        return
    result = await db.execute(select(JobRun).options(selectinload(JobRun.job)).where(JobRun.id == run_id))
    run = result.scalar_one_or_none()
    if run is None:
        raise HTTPException(status_code=404, detail="Job run not found")
    owner = run.job.owner_sub if run.job is not None else None
    assert_can_access(user, owner, detail="Job run not found")


async def submit_aag_task(
    db: AsyncSession,
    data: AagTaskCreate,
    user: AuthUser,
    request: Request,
    row: AagProviderConfig,
) -> AagArtifact:
    await assert_cited_run_visible(db, user, data.run_id)
    if data.compare_run_id is not None:
        await assert_cited_run_visible(db, user, data.compare_run_id)
    redacted, citation, meta = await compose_screen_input(db, data, user)
    if not redacted.strip():
        raise HTTPException(status_code=422, detail="Task text is empty")
    model_name = (row.model_name or "").strip()
    if not model_name:
        raise HTTPException(status_code=422, detail="Model name is required")
    safe_url = _active_base_url(row)
    host = urlparse(safe_url).hostname
    digest = input_hash(data.kind, redacted, citation)
    existing = await db.execute(
        select(AagArtifact)
        .where(
            AagArtifact.kind == data.kind,
            AagArtifact.input_hash == digest,
            AagArtifact.status == "completed",
        )
        .order_by(AagArtifact.id.desc())
        .limit(1)
    )
    cached = existing.scalars().first()
    if cached is not None:
        return cached
    artifact = AagArtifact(
        kind=data.kind,
        status="pending",
        requested_by=user.username,
        provider=row.provider,
        model_name=model_name,
        target_host=host,
        input_hash=digest,
        prompt_redacted=redacted,
        citations_json=citation,
        meta_json=meta,
        run_id=data.run_id,
    )
    db.add(artifact)
    await db.flush()
    outbox = await enqueue_run_dispatch(
        db,
        task_name=AAG_TASK_NAME,
        args=[artifact.id],
        queue=AAG_QUEUE,
        callback_kind=AAG_CALLBACK_KIND,
        callback_ref_id=artifact.id,
        correlation={
            "request_id": request.headers.get("x-request-id"),
            "run_kind": AAG_CALLBACK_KIND,
            "run_id": artifact.id,
        },
    )
    await log_audit_event(
        db,
        request,
        user,
        action="aag.task.create",
        resource_type="aag_artifact",
        resource_id=artifact.id,
        metadata={
            "kind": artifact.kind,
            "provider": artifact.provider,
            "target_host": artifact.target_host,
            "model_name": artifact.model_name,
            "input_hash": artifact.input_hash,
        },
    )
    await commit_and_try_dispatch(db, outbox_id=outbox.id, pending_entity=artifact)
    await db.refresh(outbox)
    if outbox.status == OutboxStatus.FAILED:
        artifact.status = "failed"
        artifact.error_message = "Provider task was not queued"
        artifact.finished_at = datetime.now(UTC)
    return artifact


async def retry_aag_task(
    db: AsyncSession,
    user: AuthUser,
    request: Request,
    artifact_id: int,
    row: AagProviderConfig,
) -> AagArtifact:
    """Queue the same failed explain or generation again. The stored prompt is already redacted."""
    artifact = await db.get(AagArtifact, artifact_id)
    if artifact is None or not await _artifact_visible(db, user, artifact):
        raise HTTPException(status_code=404, detail="Result not found")
    if artifact.kind not in ("explain", "generate") or artifact.status != "failed":
        raise HTTPException(status_code=409, detail="Only a failed task can be run again")
    model_name = (row.model_name or "").strip()
    if not model_name:
        raise HTTPException(status_code=422, detail="Model name is required")
    safe_url = _active_base_url(row)
    artifact.status = "pending"
    artifact.error_message = None
    artifact.response_text = None
    artifact.finished_at = None
    artifact.provider = row.provider
    artifact.model_name = model_name
    artifact.target_host = urlparse(safe_url).hostname
    meta = dict(artifact.meta_json or {})
    meta.pop("files", None)
    meta.pop("validation_errors", None)
    artifact.meta_json = meta
    await db.flush()
    outbox = await enqueue_run_dispatch(
        db,
        task_name=AAG_TASK_NAME,
        args=[artifact.id],
        queue=AAG_QUEUE,
        callback_kind=AAG_CALLBACK_KIND,
        callback_ref_id=artifact.id,
        correlation={
            "request_id": request.headers.get("x-request-id"),
            "run_kind": AAG_CALLBACK_KIND,
            "run_id": artifact.id,
        },
    )
    await log_audit_event(
        db,
        request,
        user,
        action="aag.task.retry",
        resource_type="aag_artifact",
        resource_id=artifact.id,
        metadata={
            "kind": artifact.kind,
            "provider": artifact.provider,
            "target_host": artifact.target_host,
            "model_name": artifact.model_name,
            "input_hash": artifact.input_hash,
        },
    )
    await commit_and_try_dispatch(db, outbox_id=outbox.id, pending_entity=artifact)
    await db.refresh(outbox)
    if outbox.status == OutboxStatus.FAILED:
        artifact.status = "failed"
        artifact.error_message = "Provider task was not queued"
        artifact.finished_at = datetime.now(UTC)
    return artifact


async def delete_aag_artifact(db: AsyncSession, user: AuthUser, artifact_id: int) -> AagArtifact:
    """Remove one result the caller is allowed to see. The audit run stays."""
    artifact = await db.get(AagArtifact, artifact_id)
    if artifact is None or not await _artifact_visible(db, user, artifact):
        raise HTTPException(status_code=404, detail="Result not found")
    # Copy the journal fields before flush expires the deleted row.
    kept = AagArtifact(
        id=artifact.id,
        kind=artifact.kind,
        provider=artifact.provider,
        target_host=artifact.target_host,
    )
    await db.delete(artifact)
    await db.flush()
    return kept


async def _artifact_visible(db: AsyncSession, user: AuthUser, artifact: AagArtifact) -> bool:
    if not applies_engineer_scope(user.roles, enabled=rbac_enabled()):
        return True
    if artifact.run_id is None:
        return True
    visible = await db.execute(
        select(JobRun.id)
        .join(Job, JobRun.job_id == Job.id)
        .where(JobRun.id == artifact.run_id, Job.owner_sub == user.sub)
    )
    return visible.scalar_one_or_none() is not None


def fold_aag_usage(
    grouped: list[tuple[str, str, int]],
    imported_names: list[str],
    live_profiles: set[str],
    call_outcomes: list[tuple[str, int]],
    providers: int,
    explain_runs: int,
) -> dict[str, int]:
    """Turn grouped rows into the Status counts. A removed profile is not still in the list."""
    bucket = {
        "explain": {"completed": 0, "failed": 0, "pending": 0},
        "generate": {"completed": 0, "failed": 0, "pending": 0},
    }
    for kind, status, count in grouped:
        slot = bucket.get(kind)
        if slot is None:
            continue
        key = status if status in slot else "pending"
        slot[key] += count
    in_list = sum(1 for name in imported_names if name and name in live_profiles)
    calls_total = sum(count for _, count in call_outcomes)
    calls_failed = sum(count for outcome, count in call_outcomes if outcome != "ok")

    def total(kind: str) -> int:
        return sum(bucket[kind].values())

    return {
        "explain_total": total("explain"),
        "explain_completed": bucket["explain"]["completed"],
        "explain_failed": bucket["explain"]["failed"],
        "explain_pending": bucket["explain"]["pending"],
        "generate_total": total("generate"),
        "generate_completed": bucket["generate"]["completed"],
        "generate_failed": bucket["generate"]["failed"],
        "generate_pending": bucket["generate"]["pending"],
        "profiles_in_list": in_list,
        "profiles_ready": len(imported_names) - in_list,
        "calls_total": calls_total,
        "calls_failed": calls_failed,
        "providers": providers,
        "explain_runs": explain_runs,
    }


def fold_call_metrics(
    rows: list[tuple[str, str, str, int, int, int, int]],
) -> dict[str, object]:
    """Group journal rows by model. ``rows`` are model, kind, outcome, tokens, duration sum, timed calls, count."""
    tokens_total = tokens_explain = tokens_generate = 0
    duration_sum = duration_calls = 0
    models: dict[str, dict[str, object]] = {}
    for model, kind, outcome, tokens, duration, timed, count in rows:
        tokens = max(0, int(tokens))
        duration = max(0, int(duration))
        timed = max(0, int(timed))
        count = max(0, int(count))
        tokens_total += tokens
        if kind == "explain":
            tokens_explain += tokens
        elif kind == "generate":
            tokens_generate += tokens
        duration_sum += duration
        duration_calls += timed
        name = (model or "").strip()
        slot = models.get(name)
        if slot is None:
            slot = {
                "model_name": name,
                "other": False,
                "calls": 0,
                "failed": 0,
                "tokens": 0,
                "explain_calls": 0,
                "generate_calls": 0,
            }
            models[name] = slot
        slot["calls"] = int(slot["calls"]) + count
        slot["tokens"] = int(slot["tokens"]) + tokens
        if outcome != "ok":
            slot["failed"] = int(slot["failed"]) + count
        if kind == "explain":
            slot["explain_calls"] = int(slot["explain_calls"]) + count
        elif kind == "generate":
            slot["generate_calls"] = int(slot["generate_calls"]) + count
    ranked = sorted(models.values(), key=lambda item: (-int(item["tokens"]), -int(item["calls"]), str(item["model_name"])))
    shown = ranked[:8]
    rest = ranked[8:]
    if rest:
        shown.append(
            {
                "model_name": "",
                "other": True,
                "calls": sum(int(item["calls"]) for item in rest),
                "failed": sum(int(item["failed"]) for item in rest),
                "tokens": sum(int(item["tokens"]) for item in rest),
                "explain_calls": sum(int(item["explain_calls"]) for item in rest),
                "generate_calls": sum(int(item["generate_calls"]) for item in rest),
            }
        )
    return {
        "tokens_total": tokens_total,
        "tokens_explain": tokens_explain,
        "tokens_generate": tokens_generate,
        "duration_ms_avg": duration_sum // duration_calls if duration_calls else 0,
        "models": shown,
    }


async def aag_usage(db: AsyncSession) -> dict[str, object]:
    grouped = (
        await db.execute(
            select(AagArtifact.kind, AagArtifact.status, func.count()).group_by(
                AagArtifact.kind, AagArtifact.status
            )
        )
    ).all()
    metas = (
        await db.execute(
            select(AagArtifact.meta_json).where(
                AagArtifact.kind == "generate",
                AagArtifact.status == "completed",
            )
        )
    ).scalars().all()
    imported = [str((meta or {}).get("imported_profile_name") or "").strip() for meta in metas]
    claimed = {name for name in imported if name}
    live: set[str] = set()
    if claimed:
        live = set(
            (await db.execute(select(Profile.profile_name).where(Profile.profile_name.in_(claimed)))).scalars()
        )
    call_rows = (
        await db.execute(
            select(
                AagCallLog.model_name,
                AagCallLog.kind,
                AagCallLog.outcome,
                func.coalesce(func.sum(AagCallLog.token_count), 0),
                func.coalesce(func.sum(AagCallLog.duration_ms), 0),
                func.count(AagCallLog.duration_ms),
                func.count(),
            ).group_by(AagCallLog.model_name, AagCallLog.kind, AagCallLog.outcome)
        )
    ).all()
    folded_calls = [
        (
            str(model or ""),
            str(kind or ""),
            str(outcome or ""),
            int(tokens or 0),
            int(duration or 0),
            int(timed or 0),
            int(count or 0),
        )
        for model, kind, outcome, tokens, duration, timed, count in call_rows
    ]
    outcomes: dict[str, int] = {}
    for _model, _kind, outcome, _tokens, _duration, _timed, count in folded_calls:
        outcomes[outcome] = outcomes.get(outcome, 0) + count
    providers = await db.scalar(select(func.count()).select_from(AagProviderConfig)) or 0
    explain_runs = await db.scalar(
        select(func.count(func.distinct(AagArtifact.run_id))).where(
            AagArtifact.kind == "explain",
            AagArtifact.run_id.is_not(None),
        )
    ) or 0
    counts: dict[str, object] = fold_aag_usage(
        [(str(kind), str(status), int(count)) for kind, status, count in grouped],
        imported,
        live,
        list(outcomes.items()),
        int(providers),
        int(explain_runs),
    )
    counts.update(fold_call_metrics(folded_calls))
    return counts


async def list_aag_artifacts(
    db: AsyncSession,
    user: AuthUser,
    *,
    kind: str | None,
    offset: int,
    limit: int,
) -> tuple[list[AagArtifact], int]:
    stmt = select(AagArtifact).where(AagArtifact.kind.in_(("explain", "generate")))
    if kind:
        stmt = stmt.where(AagArtifact.kind == kind)
    if applies_engineer_scope(user.roles, enabled=rbac_enabled()):
        visible_runs = select(JobRun.id).join(Job, JobRun.job_id == Job.id).where(Job.owner_sub == user.sub)
        stmt = stmt.where(or_(AagArtifact.run_id.is_(None), AagArtifact.run_id.in_(visible_runs)))
    stmt = stmt.order_by(AagArtifact.created_at.desc(), AagArtifact.id.desc())
    rows, total = await paginate_scalars(db, stmt, offset=offset, limit=limit)
    await release_deleted_profile_imports(db, rows)
    return rows, total


async def release_deleted_profile_imports(db: AsyncSession, rows: list[AagArtifact]) -> None:
    """Drop the import mark when that profile was removed from the profile list."""
    claimed = {
        str((row.meta_json or {}).get("imported_profile_name") or "").strip()
        for row in rows
    }
    claimed.discard("")
    if not claimed:
        return
    found = set(
        (await db.execute(select(Profile.profile_name).where(Profile.profile_name.in_(claimed)))).scalars()
    )
    changed = False
    for row in rows:
        meta = dict(row.meta_json or {})
        name = str(meta.get("imported_profile_name") or "").strip()
        if not name or name in found:
            continue
        meta.pop("imported_profile_name", None)
        row.meta_json = meta
        changed = True
    if changed:
        await db.commit()


def _status_value(value: object) -> str:
    return value.value if hasattr(value, "value") else str(value)


async def _completed_run(db: AsyncSession, user: AuthUser, run_id: int) -> JobRun:
    result = await db.execute(
        select(JobRun).options(selectinload(JobRun.job), selectinload(JobRun.check_results)).where(JobRun.id == run_id)
    )
    run = result.scalar_one_or_none()
    if run is None:
        raise HTTPException(status_code=404, detail="Job run not found")
    owner = run.job.owner_sub if run.job is not None else None
    assert_can_access(user, owner, detail="Job run not found")
    if _status_value(run.status) != JobStatus.COMPLETED.value:
        raise HTTPException(status_code=422, detail="Run is not completed")
    return run


_PARAMETER_FIELDS = (
    ("criticality", "criticality"),
    ("impact", "impact"),
    ("scope", "scope"),
    ("operator", "operator"),
    ("target_value", "target"),
    ("default_value", "default"),
    ("value_type", "value_type"),
    ("parser_rule", "parser"),
    ("match_pattern", "match_pattern"),
    ("check_script", "check_script"),
)


def _parameter_line(rule: dict) -> str:
    parts: list[str] = []
    for key, label in _PARAMETER_FIELDS:
        value = str(rule.get(key) or "").strip()
        if value:
            parts.append(f"{label}={value}")
    return "; ".join(parts)


def _rule_index(package_path: str | None) -> tuple[dict[str, str], dict[str, str], set[str]]:
    texts: dict[str, str] = {}
    titles: dict[str, str] = {}
    scripts: set[str] = set()
    if not package_path:
        return texts, titles, scripts
    directory = Path(package_path)
    if not directory.is_dir():
        return texts, titles, scripts
    for rule in load_profile_rules_metadata(directory):
        keys = rule_identity_keys(
            str(rule.get("tech_name") or ""),
            str(rule.get("requirement_id") or ""),
        )
        title = str(rule.get("title") or "").strip()
        explanation = str(rule.get("explanation") or "").strip()
        text = ". ".join(part for part in (title, explanation) if part)
        parameters = _parameter_line(rule)
        if parameters:
            text = f"{text}\nparameters: {parameters}".strip()
        for key in keys:
            if key:
                texts[key] = text
                if title:
                    titles[key] = title
    for script in discover_remediation_scripts(directory):
        name = str(script.get("name") or "").lower()
        if name:
            scripts.add(name)
    return texts, titles, scripts


def _finding_row(
    check: CheckResult,
    host: Host | None,
    rules: dict[str, str],
    titles: dict[str, str],
    scripts: set[str],
) -> dict:
    status = _status_value(check.status)
    host_name = None
    os_type = None
    if host is not None:
        host_name = (host.name or "").strip() or (host.hostname or "").strip() or None
        os_type = host.os_type
    rule = check.rule_tech_name
    message = redact_fragment(check.message or "")[:500]
    wider = redact_fragment(check.raw_output or "")[:1500]
    return {
        "id": check.id,
        "rule_tech_name": rule,
        "host_id": check.host_id,
        "host_name": host_name,
        "os_type": os_type,
        "message": message,
        "rule_text": rules.get(rule),
        "rule_title": titles.get(rule),
        "has_remediation": any(rule.lower() in script or script in rule.lower() for script in scripts),
        "status": status,
        "wider": wider,
    }


_CHECK_ORDER = {"fail": 0, "error": 1, "skip": 2, "pass": 3, "pending": 4}
_CANDIDATE_LIMIT = 2000


async def _run_findings(
    db: AsyncSession,
    user: AuthUser,
    run_id: int,
    *,
    limit: int | None,
) -> list[dict]:
    run = await _completed_run(db, user, run_id)
    checks = list(run.check_results)
    host_ids = {check.host_id for check in checks}
    hosts: dict[int, Host] = {}
    if host_ids:
        result = await db.execute(select(Host).where(Host.id.in_(host_ids)))
        hosts = {host.id: host for host in result.scalars().all()}
    package_path = None
    if run.job is not None and run.job.profile_id is not None:
        profile = await db.get(Profile, run.job.profile_id)
        package_path = profile.package_path if profile is not None else None
    rules, titles, scripts = _rule_index(package_path)
    rows = [_finding_row(check, hosts.get(check.host_id), rules, titles, scripts) for check in checks]
    rows.sort(
        key=lambda item: (
            _CHECK_ORDER.get(str(item["status"]).lower(), 9),
            str(item["rule_tech_name"]),
            str(item["host_name"] or ""),
        )
    )
    if limit is not None:
        return rows[:limit]
    return rows


async def list_explain_candidates(db: AsyncSession, user: AuthUser, run_id: int) -> list[AagExplainCandidate]:
    rows = []
    for item in await _run_findings(db, user, run_id, limit=_CANDIDATE_LIMIT):
        rows.append(
            AagExplainCandidate(
                id=item["id"],
                rule_tech_name=item["rule_tech_name"],
                host_id=item["host_id"],
                host_name=item["host_name"],
                os_type=item["os_type"],
                message=item["message"],
                rule_text=item["rule_text"],
                rule_title=item["rule_title"],
                has_remediation=item["has_remediation"],
                status=item["status"],
            )
        )
    return rows


async def compose_screen_input(
    db: AsyncSession,
    data: AagTaskCreate,
    user: AuthUser,
) -> tuple[str, dict | None, dict | None]:
    """Build the model fragment from stored facts. The browser does not supply numbers or raw output."""
    citation = citation_payload(
        run_id=data.run_id,
        rule_tech_name=data.rule_tech_name,
        host_id=data.host_id,
    )
    meta: dict = {}
    if data.kind == "explain":
        if data.run_id is None or not data.check_ids:
            raise HTTPException(status_code=422, detail="Select findings from a completed run")
        findings = await _run_findings(db, user, data.run_id, limit=None)
        chosen = [item for item in findings if item["id"] in set(data.check_ids)][:MAX_FINDINGS]
        if not chosen:
            raise HTTPException(status_code=422, detail="Select findings from a completed run")
        rules = [item["rule_tech_name"] for item in chosen]
        meta = {
            "check_ids": [item["id"] for item in chosen],
            "rules": rules,
            "checks": [
                {
                    "rule": item["rule_tech_name"],
                    "host": item["host_name"] or str(item["host_id"]),
                    "status": item["status"],
                    "title": item["rule_title"] or "",
                }
                for item in chosen
            ],
        }
        citation = citation_payload(run_id=data.run_id, rule_tech_name=",".join(rules))
        return build_explain_fragment(chosen, run_id=data.run_id), citation, meta
    if data.kind == "generate":
        phrase = redact_fragment(data.prompt or "")
        profile_name = redact_fragment(data.profile_name or "").strip()[:128]
        if not profile_name:
            raise HTTPException(status_code=422, detail="Profile name is required")
        if official_benchmark_name(profile_name):
            raise HTTPException(status_code=422, detail="Package cannot be signed as CIS, STIG, or FSTEK")
        if not phrase.strip():
            raise HTTPException(status_code=422, detail="Task text is empty")
        version = redact_fragment(data.profile_version or "").strip()[:32]
        target_name = redact_fragment(data.target_name or "").strip()[:128]
        vendor = redact_fragment(data.target_vendor or "").strip()[:128]
        target_version = redact_fragment(data.target_version or "").strip()[:64]
        overview = redact_fragment(data.overview or "").strip()[:500]
        purpose = redact_fragment(data.purpose or "").strip()[:2000]
        target_kind = data.target_kind if data.target_kind in {"os", "software"} else ""
        script_kind = data.script_kind if data.script_kind in {"sh", "ps1", "py"} else ""
        profile = {
            key: value
            for key, value in {
                "version": version,
                "target_kind": target_kind,
                "name": target_name,
                "vendor": vendor,
                "target_version": target_version,
                "overview": overview,
                "purpose": purpose,
                "script_kind": script_kind,
            }.items()
            if value
        }
        lines = [f"profile_name={profile_name}"]
        if version:
            lines.append(f"version={version}")
        prefix = f"{target_kind}." if target_kind else ""
        if target_name:
            lines.append(f"{prefix}name={target_name}")
        if vendor:
            lines.append(f"{prefix}vendor={vendor}")
        if target_version:
            lines.append(f"{prefix}version={target_version}")
        if overview:
            lines.append(f"overview={overview}")
        if purpose:
            lines.append(f"purpose={purpose}")
        if script_kind:
            lines.append(f"script_name=check.{script_kind}")
        lines.append(
            "Fill every omitted field from the request: version, os or software, overview, and purpose. Name the check script check.sh, check.ps1, or check.py."
        )
        return (
            "\n".join(lines) + "\n" + phrase,
            citation,
            {
                "files": None,
                "validation_errors": [],
                "profile_name": profile_name,
                "profile": profile,
            },
        )
    raise HTTPException(status_code=422, detail="Unknown AAG task")


async def update_package_draft(
    db: AsyncSession,
    artifact_id: int,
    draft: AagPackageDraft,
    user: AuthUser,
) -> AagArtifact:
    artifact = await db.get(AagArtifact, artifact_id)
    if artifact is None or artifact.kind != "generate":
        raise HTTPException(status_code=404, detail="Artifact not found")
    requested = str((artifact.meta_json or {}).get("profile_name") or "")
    files = normalize_package_files(
        {
            "description": draft.description,
            "rules": draft.rules,
            "script_name": draft.script_name,
            "script": draft.script,
        },
        profile_name=str(draft.description.get("profile_name") or requested),
    )
    staging = Path(settings.profiles_storage_path) / "_aag" / f"edit-{artifact.id}"
    errors = package_request_errors(files)
    if not errors:
        errors = write_generated_package(files, staging)
    meta = dict(artifact.meta_json or {})
    meta["edited_by"] = user.username
    meta["files"] = files
    meta["validation_errors"] = errors
    artifact.meta_json = meta
    artifact.response_text = artifact.response_text
    await db.commit()
    await db.refresh(artifact)
    return artifact


async def accept_generated_profile(
    db: AsyncSession,
    artifact_id: int,
    user: AuthUser,
) -> AagArtifact:
    artifact = await db.get(AagArtifact, artifact_id)
    if artifact is None or artifact.kind != "generate":
        raise HTTPException(status_code=404, detail="Artifact not found")
    stored = (artifact.meta_json or {}).get("files")
    requested = str((artifact.meta_json or {}).get("profile_name") or "")
    if isinstance(stored, dict):
        description = stored.get("description") if isinstance(stored.get("description"), dict) else {}
        files = normalize_package_files(
            stored,
            profile_name=str(description.get("profile_name") or requested),
        )
    else:
        files = generated_package_files(artifact.response_text or "", profile_name=requested)
    staging = Path(settings.profiles_storage_path) / "_aag" / f"accept-{artifact.id}"
    errors = package_request_errors(files)
    if not errors:
        errors = write_generated_package(files, staging)
    if errors:
        meta = dict(artifact.meta_json or {})
        meta["files"] = files
        meta["validation_errors"] = errors
        artifact.meta_json = meta
        await db.commit()
        raise HTTPException(status_code=422, detail="; ".join(errors))
    description = files.get("description") if isinstance(files.get("description"), dict) else {}
    name = str(description.get("profile_name") or description.get("tech_name") or "").strip()
    if not name:
        raise HTTPException(status_code=422, detail="profile_name is required")
    existing = await db.execute(select(func.count()).select_from(Profile).where(Profile.profile_name == name))
    if existing.scalar_one():
        raise HTTPException(status_code=409, detail="Profile name is already in use")
    try:
        await ProfileService().import_from_path(db, str(staging), replace_existing=False)
    except ValueError as exc:
        message = str(exc)
        if "already imported" in message.lower():
            raise HTTPException(status_code=409, detail="Profile name is already in use") from exc
        raise HTTPException(status_code=422, detail=message) from exc
    meta = dict(artifact.meta_json or {})
    meta["accepted_by"] = user.username
    meta["imported_profile_name"] = name
    meta["validation_errors"] = []
    artifact.meta_json = meta
    await db.commit()
    await db.refresh(artifact)
    return artifact
