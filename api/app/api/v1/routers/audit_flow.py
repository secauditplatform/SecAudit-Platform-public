import json
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import AuthUser, require_roles
from app.core.roles import require_operate
from app.core.config import settings
from app.core.database import get_db
from app.models import AuditFlowCredential, AuditFlowRun, AuditFlowStatus, AuditFlowTemplate, Profile, UserRole
from app.schemas import (
    AuditFlowCreate,
    AuditFlowCredentialAdd,
    AuditFlowHostsPatch,
    AuditFlowInventoryDriftReport,
    AuditFlowLogEntry,
    AuditFlowRunRead,
    AuditFlowTemplateCreate,
    AuditFlowTemplateRead,
    AuditFlowTemplateUpdate,
)
from app.services.audit_flow import (
    EDITABLE_STATUSES,
    attach_snapshot_credentials,
    cleanup_expired,
    clear_retryable_skip,
    apply_host_selection,
    delete_run_artifacts,
    encrypt_flow_secret,
    execute_run,
    load_run,
    present_run,
    snapshot_credentials,
    template_to_read,
    validate_credentials,
    validate_targets,
)
from app.services.audit_log import log_audit_event
from app.services.dispatch import commit_and_try_dispatch, enqueue_run_dispatch
from app.services.task_outbox import try_dispatch_outbox_immediate
from app.services.object_rbac import apply_owner_scope, assert_can_access, assign_owner
from app.services.scan_limits import resolve_max_cidr_prefix_len
from secaudit_core.audit_flow_state import (
    append_audit_flow_log,
    get_audit_flow_progress,
    request_audit_flow_cancel,
)
from secaudit_core.redis_client import async_redis
from secaudit_core.sensitive_data import redact_live_log_frame

router = APIRouter()
_OPERATE = require_roles(UserRole.OPERATOR, UserRole.ADMIN)


@router.get("/runs", response_model=list[AuditFlowRunRead])
async def list_audit_flow_runs(
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_operate),
) -> list[AuditFlowRunRead]:
    await cleanup_expired(db)
    stmt = select(AuditFlowRun).order_by(AuditFlowRun.created_at.desc()).limit(50)
    stmt = apply_owner_scope(stmt, AuditFlowRun.owner_sub, user)
    result = await db.execute(stmt)
    runs = result.scalars().all()
    payload = []
    for run in runs:
        loaded = await load_run(db, run.id)
        if loaded:
            payload.append(AuditFlowRunRead.model_validate(await present_run(db, loaded)))
    await db.commit()
    return payload


@router.get("/runs/compare", response_model=AuditFlowInventoryDriftReport)
async def compare_audit_flow_runs(
    left_run_id: int,
    right_run_id: int,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_operate),
) -> AuditFlowInventoryDriftReport:
    from app.services.audit_flow_inventory_drift import fetch_audit_flow_inventory_drift

    return await fetch_audit_flow_inventory_drift(
        db, user, left_run_id=left_run_id, right_run_id=right_run_id
    )


@router.post("/runs", response_model=AuditFlowRunRead, status_code=201)
async def start_audit_flow(
    data: AuditFlowCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(_OPERATE),
) -> AuditFlowRunRead:
    try:
        targets = validate_targets(data.targets, max_prefix_len=resolve_max_cidr_prefix_len(user))
        creds = validate_credentials([item.model_dump() for item in data.credentials])
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    run = AuditFlowRun(
        status=AuditFlowStatus.PENDING,
        targets_json=targets,
        save_to_inventory=bool(data.save_to_inventory),
    )
    assign_owner(run, user)
    db.add(run)
    await db.flush()
    for item in creds:
        db.add(
            AuditFlowCredential(
                run_id=run.id,
                label=item["label"],
                credential_type=item["credential_type"],
                username=item["username"],
                encrypted_secret=encrypt_flow_secret(item["secret"]),
                encrypted_key_passphrase=(
                    encrypt_flow_secret(item["key_passphrase"])
                    if item.get("key_passphrase")
                    else None
                ),
                service_username=item.get("service_username"),
                encrypted_service_secret=(
                    encrypt_flow_secret(item["service_secret"])
                    if item.get("service_secret")
                    else None
                ),
            )
        )
    await db.flush()
    outbox = await enqueue_run_dispatch(
        db,
        task_name="app.tasks.audit_flow.run_audit_flow_scan_task",
        args=[run.id],
        queue="inventory",
        callback_kind="audit_flow_run",
        callback_ref_id=run.id,
        correlation={"started_by_sub": user.sub, "audit_flow_run_id": run.id},
    )
    await log_audit_event(
        db,
        request,
        user,
        action="audit_flow.create",
        resource_type="audit_flow_run",
        resource_id=run.id,
        resource_name=",".join(targets)[:256],
    )
    await commit_and_try_dispatch(db, outbox_id=outbox.id, pending_entity=run)
    append_audit_flow_log(settings.redis_url, run.id, f"Task #{run.id} queued")
    if run.status == AuditFlowStatus.FAILED:
        raise HTTPException(status_code=503, detail=run.error_message or "Failed to dispatch AuditFlow")
    loaded = await load_run(db, run.id)
    return AuditFlowRunRead.model_validate(await present_run(db, loaded or run))


@router.get("/runs/{run_id}", response_model=AuditFlowRunRead)
async def get_audit_flow_run(
    run_id: int,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_operate),
) -> AuditFlowRunRead:
    run = await load_run(db, run_id)
    if not run:
        raise HTTPException(status_code=404, detail="AuditFlow run not found")
    assert_can_access(user, run.owner_sub)
    payload = await present_run(db, run)
    await db.commit()
    payload["progress"] = get_audit_flow_progress(settings.redis_url, run_id)
    return AuditFlowRunRead.model_validate(payload)


@router.get("/runs/{run_id}/logs", response_model=list[AuditFlowLogEntry])
async def get_audit_flow_run_logs(
    run_id: int,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_operate),
) -> list[AuditFlowLogEntry]:
    run = await load_run(db, run_id)
    if not run:
        raise HTTPException(status_code=404, detail="AuditFlow run not found")
    assert_can_access(user, run.owner_sub)
    client = async_redis(settings.redis_url, settings=settings)
    try:
        raw = await client.lrange(f"audit_flow_run_logs:{run_id}", 0, 499)
        entries: list[AuditFlowLogEntry] = []
        for item in reversed(raw):
            try:
                entries.append(AuditFlowLogEntry(**json.loads(redact_live_log_frame(item))))
            except (TypeError, ValueError):
                continue
        return entries
    finally:
        await client.aclose()


@router.post("/runs/{run_id}/cancel", response_model=AuditFlowRunRead)
async def cancel_audit_flow_run(
    run_id: int,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(_OPERATE),
) -> AuditFlowRunRead:
    run = await load_run(db, run_id)
    if not run:
        raise HTTPException(status_code=404, detail="AuditFlow run not found")
    assert_can_access(user, run.owner_sub)
    if run.status in {AuditFlowStatus.PENDING, AuditFlowStatus.SCANNING, AuditFlowStatus.RUNNING}:
        run.status = AuditFlowStatus.CANCELLED
        run.finished_at = datetime.now(UTC)
        run.error_message = "Cancelled by user"
        request_audit_flow_cancel(settings.redis_url, run_id)
        await db.commit()
    loaded = await load_run(db, run.id)
    return AuditFlowRunRead.model_validate(await present_run(db, loaded or run))


@router.patch("/runs/{run_id}/hosts", response_model=AuditFlowRunRead)
async def patch_audit_flow_hosts(
    run_id: int,
    data: AuditFlowHostsPatch,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(_OPERATE),
) -> AuditFlowRunRead:
    run = await load_run(db, run_id)
    if not run:
        raise HTTPException(status_code=404, detail="AuditFlow run not found")
    assert_can_access(user, run.owner_sub)
    if run.status not in EDITABLE_STATUSES:
        raise HTTPException(status_code=409, detail="Hosts can only be edited after the scan finishes")
    by_id = {h.id: h for h in run.hosts}
    cred_by_id = {c.id: c for c in run.credentials}
    for item in data.hosts:
        row = by_id.get(item.id)
        if row is None:
            raise HTTPException(status_code=404, detail=f"Host {item.id} not found")
        if row.job_run_id and (
            item.selected is not None
            or "profile_id" in item.model_fields_set
            or "credential_id" in item.model_fields_set
        ):
            raise HTTPException(status_code=409, detail="Host already launched")
        if item.selected is not None:
            apply_host_selection(row, item.selected)
        if "profile_id" in item.model_fields_set:
            if item.profile_id is None:
                row.profile_id = None
                row.profile_name = None
                row.confidence = 0
                if not row.job_run_id:
                    apply_host_selection(row, False)
            else:
                profile = await db.get(Profile, item.profile_id)
                if not profile:
                    raise HTTPException(status_code=404, detail="Profile not found")
                row.profile_id = profile.id
                row.profile_name = profile.profile_name
                row.confidence = 100
                row.selected = True
                clear_retryable_skip(row)
        if "credential_id" in item.model_fields_set:
            if item.credential_id is None:
                row.credential_id = None
            else:
                cred = cred_by_id.get(item.credential_id)
                if cred is None:
                    raise HTTPException(status_code=404, detail="Credential not found")
                row.credential_id = cred.id
                row.selected = True
                clear_retryable_skip(row)
        if item.extra_profiles is not None:
            current = {
                int(entry["profile_id"]): dict(entry)
                for entry in (row.extra_profiles_json or [])
                if entry.get("profile_id")
            }
            for extra in item.extra_profiles:
                entry = current.get(extra.profile_id) or {
                    "profile_id": extra.profile_id,
                    "profile_name": "",
                    "confidence": 0,
                }
                if not entry.get("profile_name"):
                    profile = await db.get(Profile, extra.profile_id)
                    if profile:
                        entry["profile_name"] = profile.profile_name
                    elif entry.get("label"):
                        entry["profile_name"] = entry["label"]
                entry["selected"] = extra.selected
                current[extra.profile_id] = entry
            row.extra_profiles_json = list(current.values())
    await db.commit()
    run = await load_run(db, run_id)
    return AuditFlowRunRead.model_validate(await present_run(db, run))


@router.post("/runs/{run_id}/credentials", response_model=AuditFlowRunRead)
async def add_audit_flow_credential(
    run_id: int,
    data: AuditFlowCredentialAdd,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(_OPERATE),
) -> AuditFlowRunRead:
    run = await load_run(db, run_id)
    if not run:
        raise HTTPException(status_code=404, detail="AuditFlow run not found")
    assert_can_access(user, run.owner_sub)
    if run.status not in EDITABLE_STATUSES:
        raise HTTPException(status_code=409, detail="Credentials can only be added after the scan finishes")
    if len(run.credentials) >= 20:
        raise HTTPException(status_code=400, detail="At most 20 credential pairs are allowed")
    host_row = None
    if data.host_id is not None:
        host_row = next((row for row in run.hosts if row.id == data.host_id), None)
        if host_row is None:
            raise HTTPException(status_code=404, detail=f"Host {data.host_id} not found")
        if host_row.job_run_id:
            raise HTTPException(status_code=409, detail="Host already launched")
    try:
        creds = validate_credentials([data.model_dump(exclude={"host_id"})])
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    item = creds[0]
    credential = AuditFlowCredential(
        run_id=run.id,
        label=item["label"],
        credential_type=item["credential_type"],
        username=item["username"],
        encrypted_secret=encrypt_flow_secret(item["secret"]),
        encrypted_key_passphrase=(
            encrypt_flow_secret(item["key_passphrase"]) if item.get("key_passphrase") else None
        ),
        service_username=item.get("service_username"),
        encrypted_service_secret=(
            encrypt_flow_secret(item["service_secret"]) if item.get("service_secret") else None
        ),
    )
    db.add(credential)
    await db.flush()
    if host_row is not None:
        host_row.credential_id = credential.id
        host_row.selected = True
        clear_retryable_skip(host_row)
    await db.commit()
    run = await load_run(db, run_id)
    return AuditFlowRunRead.model_validate(await present_run(db, run))


@router.post("/runs/{run_id}/execute", response_model=AuditFlowRunRead)
async def execute_audit_flow(
    run_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(_OPERATE),
) -> AuditFlowRunRead:
    run = await load_run(db, run_id)
    if not run:
        raise HTTPException(status_code=404, detail="AuditFlow run not found")
    assert_can_access(user, run.owner_sub)
    try:
        run, outbox_ids = await execute_run(db, user, run)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    append_audit_flow_log(
        settings.redis_url,
        run.id,
        f"Starting compliance checks for task #{run.id}",
    )
    await log_audit_event(
        db,
        request,
        user,
        action="audit_flow.execute",
        resource_type="audit_flow_run",
        resource_id=run.id,
    )
    await db.commit()
    for outbox_id in outbox_ids:
        await try_dispatch_outbox_immediate(
            outbox_id,
            broker_url=settings.celery_broker_url,
            database_url=settings.database_url_sync,
            metrics_redis_url=settings.redis_url,
        )
    run = await load_run(db, run_id)
    return AuditFlowRunRead.model_validate(await present_run(db, run))


@router.delete("/runs/{run_id}", status_code=204)
async def delete_audit_flow_run(
    run_id: int,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(_OPERATE),
) -> None:
    run = await load_run(db, run_id)
    if not run:
        raise HTTPException(status_code=404, detail="AuditFlow run not found")
    assert_can_access(user, run.owner_sub)
    await delete_run_artifacts(db, run)
    await db.delete(run)
    await db.commit()


def _validate_schedule_update(
    *,
    is_scheduled: bool | None,
    cron_expression: str | None,
    current_scheduled: bool,
    current_cron: str | None,
) -> tuple[bool, str | None]:
    scheduled = current_scheduled if is_scheduled is None else bool(is_scheduled)
    cron = current_cron if cron_expression is None and is_scheduled is None else cron_expression
    if is_scheduled is False:
        cron = None
    if scheduled and not cron:
        raise HTTPException(status_code=400, detail="cron_expression is required when is_scheduled is true")
    if not scheduled:
        cron = None
    return scheduled, cron


@router.get("/templates", response_model=list[AuditFlowTemplateRead])
async def list_audit_flow_templates(
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_operate),
) -> list[AuditFlowTemplateRead]:
    stmt = select(AuditFlowTemplate).order_by(AuditFlowTemplate.name)
    stmt = apply_owner_scope(stmt, AuditFlowTemplate.owner_sub, user)
    result = await db.execute(stmt)
    return [AuditFlowTemplateRead.model_validate(template_to_read(item)) for item in result.scalars().all()]


@router.post("/templates", response_model=AuditFlowTemplateRead, status_code=201)
async def create_audit_flow_template(
    data: AuditFlowTemplateCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(_OPERATE),
) -> AuditFlowTemplateRead:
    try:
        targets = validate_targets(data.targets, max_prefix_len=resolve_max_cidr_prefix_len(user))
        creds = validate_credentials([item.model_dump() for item in data.credentials])
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    existing = await db.execute(select(AuditFlowTemplate).where(AuditFlowTemplate.name == data.name))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="AuditFlow template with this name already exists")

    template = AuditFlowTemplate(
        name=data.name,
        description=(data.description or "").strip() or None,
        targets_json=targets,
        credentials_json=snapshot_credentials(creds),
        save_to_inventory=bool(data.save_to_inventory),
        cron_expression=data.cron_expression if data.is_scheduled else None,
        is_scheduled=bool(data.is_scheduled),
        is_active=bool(data.is_active),
    )
    assign_owner(template, user)
    db.add(template)
    await db.flush()
    await log_audit_event(
        db,
        request,
        user,
        action="audit_flow_template.create",
        resource_type="audit_flow_template",
        resource_id=template.id,
        resource_name=template.name,
    )
    await db.commit()
    await db.refresh(template)
    return AuditFlowTemplateRead.model_validate(template_to_read(template))


@router.get("/templates/{template_id}", response_model=AuditFlowTemplateRead)
async def get_audit_flow_template(
    template_id: int,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_operate),
) -> AuditFlowTemplateRead:
    template = await db.get(AuditFlowTemplate, template_id)
    if not template:
        raise HTTPException(status_code=404, detail="AuditFlow template not found")
    assert_can_access(user, template.owner_sub)
    return AuditFlowTemplateRead.model_validate(template_to_read(template))


@router.patch("/templates/{template_id}", response_model=AuditFlowTemplateRead)
async def update_audit_flow_template(
    template_id: int,
    data: AuditFlowTemplateUpdate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(_OPERATE),
) -> AuditFlowTemplateRead:
    template = await db.get(AuditFlowTemplate, template_id)
    if not template:
        raise HTTPException(status_code=404, detail="AuditFlow template not found")
    assert_can_access(user, template.owner_sub)

    payload = data.model_dump(exclude_unset=True)
    if "name" in payload and payload["name"] != template.name:
        clash = await db.execute(
            select(AuditFlowTemplate).where(
                AuditFlowTemplate.name == payload["name"],
                AuditFlowTemplate.id != template_id,
            )
        )
        if clash.scalar_one_or_none():
            raise HTTPException(status_code=409, detail="AuditFlow template with this name already exists")
        template.name = payload["name"]

    if "description" in payload:
        template.description = (payload["description"] or "").strip() or None
    if "save_to_inventory" in payload:
        template.save_to_inventory = bool(payload["save_to_inventory"])
    if "is_active" in payload:
        template.is_active = bool(payload["is_active"])

    if "targets" in payload:
        try:
            template.targets_json = validate_targets(
                payload["targets"], max_prefix_len=resolve_max_cidr_prefix_len(user)
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    if "credentials" in payload:
        try:
            creds = validate_credentials([item.model_dump() for item in data.credentials or []])
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        template.credentials_json = snapshot_credentials(creds)

    if "is_scheduled" in payload or "cron_expression" in payload:
        scheduled, cron = _validate_schedule_update(
            is_scheduled=payload.get("is_scheduled"),
            cron_expression=payload.get("cron_expression"),
            current_scheduled=bool(template.is_scheduled),
            current_cron=template.cron_expression,
        )
        template.is_scheduled = scheduled
        template.cron_expression = cron

    await log_audit_event(
        db,
        request,
        user,
        action="audit_flow_template.update",
        resource_type="audit_flow_template",
        resource_id=template.id,
        resource_name=template.name,
    )
    await db.commit()
    await db.refresh(template)
    return AuditFlowTemplateRead.model_validate(template_to_read(template))


@router.delete("/templates/{template_id}", status_code=204)
async def delete_audit_flow_template(
    template_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(_OPERATE),
) -> None:
    template = await db.get(AuditFlowTemplate, template_id)
    if not template:
        raise HTTPException(status_code=404, detail="AuditFlow template not found")
    assert_can_access(user, template.owner_sub)
    await log_audit_event(
        db,
        request,
        user,
        action="audit_flow_template.delete",
        resource_type="audit_flow_template",
        resource_id=template.id,
        resource_name=template.name,
    )
    await db.delete(template)
    await db.commit()


@router.post("/templates/{template_id}/run", response_model=AuditFlowRunRead, status_code=201)
async def run_audit_flow_template(
    template_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(_OPERATE),
) -> AuditFlowRunRead:
    template = await db.get(AuditFlowTemplate, template_id)
    if not template:
        raise HTTPException(status_code=404, detail="AuditFlow template not found")
    assert_can_access(user, template.owner_sub)
    if not template.is_active:
        raise HTTPException(status_code=400, detail="AuditFlow template is inactive")

    run = AuditFlowRun(
        status=AuditFlowStatus.PENDING,
        targets_json=list(template.targets_json or []),
        save_to_inventory=bool(template.save_to_inventory),
        template_id=template.id,
    )
    assign_owner(run, user)
    db.add(run)
    await db.flush()
    for row in attach_snapshot_credentials(run.id, template.credentials_json or []):
        db.add(row)
    await db.flush()

    outbox = await enqueue_run_dispatch(
        db,
        task_name="app.tasks.audit_flow.run_audit_flow_scan_task",
        args=[run.id],
        queue="inventory",
        callback_kind="audit_flow_run",
        callback_ref_id=run.id,
        correlation={
            "started_by_sub": user.sub,
            "audit_flow_run_id": run.id,
            "audit_flow_template_id": template.id,
            "source": "template",
        },
    )
    await log_audit_event(
        db,
        request,
        user,
        action="audit_flow_template.run",
        resource_type="audit_flow_template",
        resource_id=template.id,
        resource_name=template.name,
    )
    await commit_and_try_dispatch(db, outbox_id=outbox.id, pending_entity=run)
    append_audit_flow_log(settings.redis_url, run.id, f"Task #{run.id} queued from template «{template.name}»")
    if run.status == AuditFlowStatus.FAILED:
        raise HTTPException(status_code=503, detail=run.error_message or "Failed to dispatch AuditFlow")
    loaded = await load_run(db, run.id)
    return AuditFlowRunRead.model_validate(await present_run(db, loaded or run))
