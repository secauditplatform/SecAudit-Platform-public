"""AAG-0 connection screen: one provider per instance, secret-free call journal.

Advisory contour only. This router never reads or writes check results and
never starts jobs, scans, or remediation. Task screens (AAG-1+) will reuse
the provider stored here; they never accept their own URL or key.
"""

from __future__ import annotations

import hashlib
import time
from datetime import UTC, datetime
from urllib.parse import urlparse

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import AuthUser, require_roles
from app.core.blocking import run_blocking
from app.core.config import settings
from app.core.database import get_db
from app.core.secrets import encrypt_secret
from app.models import AagArtifact, AagCallLog, AagProviderConfig, UserRole
from app.pagination import paginate_scalars, pagination_params
from app.schemas import (
    AagArtifactRead,
    AagCallLogRead,
    AagConnectionRead,
    AagConnectionTestRead,
    AagConnectionUpdate,
    AagExplainCandidate,
    AagExplainSection,
    AagPackageDraft,
    AagParagraph,
    AagStatusRead,
    AagTaskCreate,
    PaginatedResponse,
)
from app.services.aag_tasks import (
    accept_generated_profile,
    contour_switch,
    delete_aag_artifact,
    list_aag_artifacts,
    list_explain_candidates,
    retry_aag_task,
    submit_aag_task,
    task_submission_block,
    update_package_draft,
)
from secaudit_core.aag_client import (
    AAG_MAX_TIMEOUT_SECONDS,
    annotate_paragraphs,
    explain_section_confirmed,
    parse_explain_sections,
)
from app.services.audit_log import log_audit_event
from secaudit_core.sensitive_data import redact_sensitive
from secaudit_core.url_safety import UnsafeOutboundURLError, validate_outbound_webhook_url

router = APIRouter()

PROBE_PATH = "/v1/models"
PROBE_INPUT_KIND = "aag-connection-test"


def target_host(base_url: str | None) -> str | None:
    """Destination host for the call journal and status card (never a secret)."""
    if not base_url:
        return None
    try:
        return urlparse(base_url).hostname
    except ValueError:
        return None


def probe_url(base_url: str) -> str:
    """OpenAI-compatible models endpoint under the configured base URL."""
    cleaned = base_url.rstrip("/")
    if cleaned.endswith("/v1"):
        return f"{cleaned}/models"
    return f"{cleaned}{PROBE_PATH}"


def probe_input_hash(provider: str, host: str | None, model_name: str | None) -> str:
    """Hash of the probe descriptor — the journal stores this, never a prompt."""
    descriptor = f"{PROBE_INPUT_KIND}:{provider}:{host or ''}:{model_name or ''}"
    return hashlib.sha256(descriptor.encode("utf-8")).hexdigest()


def validate_connection_input(data: AagConnectionUpdate, *, demo_mode: bool) -> str | None:
    """Validate an admin connection save. Returns the active base URL (if any).

    Raises HTTPException on demo/external conflicts, missing URLs, or SSRF
    policy violations. Pure function — unit-tested without a database.
    """
    provider = data.provider
    if provider == "none":
        return None
    if provider == "external" and demo_mode:
        raise HTTPException(status_code=403, detail="External AI API is disabled in demo mode")
    if provider == "internal":
        base_url = (data.internal_base_url or "").strip()
        if not base_url:
            raise HTTPException(status_code=422, detail="Internal server address is required")
        try:
            # Perimeter server: RFC1918 allowed, but never loopback/link-local/metadata.
            return validate_outbound_webhook_url(base_url, allow_http=True, allow_private=True)
        except UnsafeOutboundURLError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
    base_url = (data.external_base_url or "").strip()
    if not base_url:
        raise HTTPException(status_code=422, detail="External API base URL is required")
    try:
        return validate_outbound_webhook_url(
            base_url,
            allow_http=False,
            allow_private=settings.outbound_webhooks_allow_private,
        )
    except UnsafeOutboundURLError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


def connection_to_read(row: AagProviderConfig) -> AagConnectionRead:
    return AagConnectionRead(
        id=row.id,
        provider=row.provider,  # type: ignore[arg-type]
        internal_base_url=row.internal_base_url,
        external_base_url=row.external_base_url,
        model_name=row.model_name,
        has_external_key=bool(row.encrypted_external_key),
        enabled=bool(row.enabled),
        selected=bool(row.selected),
        timeout_seconds=row.timeout_seconds,
        max_tokens=row.max_tokens,
        updated_by=row.updated_by,
        updated_at=row.updated_at,
    )


async def get_or_default_row(db: AsyncSession) -> AagProviderConfig:
    """The working provider. An unsaved default means none is selected."""
    result = await db.execute(
        select(AagProviderConfig).where(AagProviderConfig.selected.is_(True)).limit(1)
    )
    row = result.scalars().first()
    if row is not None:
        return row
    return AagProviderConfig(
        provider="none",
        timeout_seconds=settings.ai_timeout_seconds,
        max_tokens=settings.ai_max_tokens,
    )


async def _provider_or_404(db: AsyncSession, config_id: int) -> AagProviderConfig:
    row = await db.get(AagProviderConfig, config_id)
    if row is None or row.provider == "none":
        raise HTTPException(status_code=404, detail="Provider not found")
    return row


def _probe_once(url: str, timeout_seconds: int) -> None:
    """One short no-data request. Any HTTP answer means the provider responds."""
    with httpx.Client(timeout=timeout_seconds, follow_redirects=False) as client:
        client.get(url)


@router.get("/status", response_model=AagStatusRead)
async def get_aag_status(
    db: AsyncSession = Depends(get_db),
    _: AuthUser = Depends(require_roles(UserRole.OPERATOR, UserRole.AUDITOR)),
) -> AagStatusRead:
    row = await get_or_default_row(db)
    any_saved = (
        await db.execute(select(AagProviderConfig.id).limit(1))
    ).scalar_one_or_none() is not None
    persisted = row.id is not None
    # Saved providers exist, but none is the working one: stay off.
    if any_saved and not persisted:
        provider = "none"
        model_name = None
        enabled = False
    else:
        provider = row.provider if persisted else settings.ai_provider
        model_name = row.model_name if persisted else settings.ai_model
        enabled = contour_switch(
            saved=row.enabled if persisted else None,
            env_enabled=settings.ai_enabled,
        ) and provider != "none"
    reachable = row.last_test_ok if row.id is not None else None
    return AagStatusRead(
        enabled=enabled,
        provider=provider if provider in ("none", "internal", "external") else "none",  # type: ignore[arg-type]
        model_name=model_name,
        reachable=reachable,
        demo_mode=settings.demo_mode,
    )


@router.get("/connection", response_model=AagConnectionRead)
async def get_aag_connection(
    db: AsyncSession = Depends(get_db),
    _: AuthUser = Depends(require_roles(UserRole.ADMIN)),
) -> AagConnectionRead:
    row = await get_or_default_row(db)
    return connection_to_read(row)


@router.put("/connection", response_model=AagConnectionRead)
async def save_aag_connection(
    data: AagConnectionUpdate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_roles(UserRole.ADMIN)),
) -> AagConnectionRead:
    if data.provider == "none":
        raise HTTPException(status_code=422, detail="Choose a provider")
    safe_url = validate_connection_input(data, demo_mode=settings.demo_mode)
    row = await db.get(AagProviderConfig, data.id) if data.id is not None else None
    if data.id is not None and row is None:
        raise HTTPException(status_code=404, detail="Provider not found")
    previous_host = target_host(row.external_base_url or row.internal_base_url) if row else None
    previous_provider = row.provider if row else "none"
    previous_internal = row.internal_base_url if row else None
    previous_external = row.external_base_url if row else None
    previous_model = row.model_name if row else None
    previous_timeout = row.timeout_seconds if row else None
    previous_tokens = row.max_tokens if row else None
    make_online = False
    if row is None:
        row = AagProviderConfig()
        db.add(row)
        selected = await db.execute(
            select(AagProviderConfig.id).where(AagProviderConfig.selected.is_(True)).limit(1)
        )
        make_online = selected.scalar_one_or_none() is None

    row.provider = data.provider
    row.enabled = True if make_online else bool(data.enabled)
    if make_online:
        row.selected = True
    row.internal_base_url = (data.internal_base_url or "").strip() or None
    row.external_base_url = (data.external_base_url or "").strip() or None
    row.model_name = (data.model_name or "").strip() or None
    if data.timeout_seconds is not None:
        row.timeout_seconds = data.timeout_seconds
    elif previous_timeout is None:
        row.timeout_seconds = AAG_MAX_TIMEOUT_SECONDS
    if data.max_tokens is not None:
        row.max_tokens = data.max_tokens
    # Empty key field keeps the stored key; only an explicit value rotates it.
    # A key is only ever stored for the external provider.
    if data.provider == "external":
        if data.external_api_key:
            row.encrypted_external_key = encrypt_secret(data.external_api_key, settings)
    else:
        row.encrypted_external_key = None
    row.updated_by = user.username
    probe_changed = (
        previous_provider != row.provider
        or (previous_internal or None) != row.internal_base_url
        or (previous_external or None) != row.external_base_url
        or (previous_model or None) != row.model_name
        or previous_timeout != row.timeout_seconds
        or previous_tokens != row.max_tokens
        or bool(data.external_api_key)
    )
    if probe_changed or row.id is None:
        row.last_test_ok = None
        row.last_test_at = None
    await db.flush()

    next_host = target_host(safe_url)
    await log_audit_event(
        db,
        request,
        user,
        action="aag.connection.update",
        resource_type="aag_connection",
        resource_id=row.id,
        metadata={
            "provider": data.provider,
            "enabled": bool(data.enabled),
            "target_host": next_host,
            "model_name": row.model_name,
            "url_changed": previous_host != next_host,
            "has_external_key": bool(row.encrypted_external_key),
        },
    )
    # updated_at is filled by the database on flush; a sync read would raise MissingGreenlet.
    await db.refresh(row)
    return connection_to_read(row)


@router.get("/providers", response_model=list[AagConnectionRead])
async def list_aag_providers(
    db: AsyncSession = Depends(get_db),
    _: AuthUser = Depends(require_roles(UserRole.ADMIN)),
) -> list[AagConnectionRead]:
    result = await db.execute(
        select(AagProviderConfig)
        .where(AagProviderConfig.provider != "none")
        .order_by(AagProviderConfig.id)
    )
    return [connection_to_read(row) for row in result.scalars()]


@router.post("/providers/{provider_id}/select", response_model=AagConnectionRead)
async def select_aag_provider(
    provider_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_roles(UserRole.ADMIN)),
) -> AagConnectionRead:
    """Make one saved provider the working one. The others stay offline."""
    target = await _provider_or_404(db, provider_id)
    result = await db.execute(select(AagProviderConfig))
    for row in result.scalars():
        row.selected = row.id == target.id
        if row.id != target.id:
            row.enabled = False
    target.enabled = True
    target.updated_by = user.username
    await db.flush()
    await log_audit_event(
        db,
        request,
        user,
        action="aag.connection.select",
        resource_type="aag_connection",
        resource_id=target.id,
        metadata={"provider": target.provider, "model_name": target.model_name},
    )
    await db.refresh(target)
    return connection_to_read(target)


@router.delete("/providers/{provider_id}", status_code=204, response_class=Response)
async def delete_aag_provider(
    provider_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_roles(UserRole.ADMIN)),
) -> Response:
    row = await _provider_or_404(db, provider_id)
    provider = row.provider
    await db.delete(row)
    await db.flush()
    await log_audit_event(
        db,
        request,
        user,
        action="aag.connection.delete",
        resource_type="aag_connection",
        resource_id=provider_id,
        metadata={"provider": provider},
    )
    return Response(status_code=204)


@router.post("/connection/test", response_model=AagConnectionTestRead)
async def test_aag_connection(
    request: Request,
    provider_id: int | None = None,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_roles(UserRole.ADMIN)),
) -> AagConnectionTestRead:
    row = await _provider_or_404(db, provider_id) if provider_id is not None else await get_or_default_row(db)
    if row.id is None or row.provider == "none":
        raise HTTPException(status_code=422, detail="No AAG provider configured")
    if row.provider == "external" and settings.demo_mode:
        raise HTTPException(status_code=403, detail="External AI API is disabled in demo mode")
    base_url = row.external_base_url if row.provider == "external" else row.internal_base_url
    if not base_url:
        raise HTTPException(status_code=422, detail="Provider address is not configured")
    try:
        safe_url = validate_outbound_webhook_url(
            base_url,
            allow_http=row.provider == "internal",
            allow_private=True if row.provider == "internal" else settings.outbound_webhooks_allow_private,
        )
    except UnsafeOutboundURLError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    host = target_host(safe_url)
    url = probe_url(safe_url)
    timeout = max(1, min(row.timeout_seconds or settings.ai_timeout_seconds, 60))
    started = time.perf_counter()
    try:
        await run_blocking(_probe_once, url, timeout)
    except Exception as exc:
        duration_ms = int((time.perf_counter() - started) * 1000)
        safe_error = redact_sensitive(str(exc))
        error_code = "timeout" if "timeout" in type(exc).__name__.lower() else "network"
        row.last_test_ok = False
        row.last_test_at = datetime.now(UTC)
        db.add(
            AagCallLog(
                provider=row.provider,
                target_host=host,
                model_name=row.model_name,
                input_hash=probe_input_hash(row.provider, host, row.model_name),
                kind="test",
                outcome="failed",
                error_code=error_code,
                duration_ms=duration_ms,
                in_perimeter=row.provider == "internal",
                created_by=user.username,
            )
        )
        await db.flush()
        await log_audit_event(
            db,
            request,
            user,
            action="aag.connection.test",
            resource_type="aag_connection",
            resource_id=row.id,
            outcome="failed",
            metadata={
                "provider": row.provider,
                "target_host": host,
                "model_name": row.model_name,
                "error": safe_error,
            },
        )
        return AagConnectionTestRead(
            ok=False,
            provider=row.provider,  # type: ignore[arg-type]
            host=host,
            model_name=row.model_name,
            message="Provider does not respond",
        )

    entry = AagCallLog(
        provider=row.provider,
        target_host=host,
        model_name=row.model_name,
        input_hash=probe_input_hash(row.provider, host, row.model_name),
        kind="test",
        outcome="ok",
        duration_ms=int((time.perf_counter() - started) * 1000),
        in_perimeter=row.provider == "internal",
        created_by=user.username,
    )
    db.add(entry)
    row.last_test_ok = True
    row.last_test_at = datetime.now(UTC)
    await db.flush()
    await log_audit_event(
        db,
        request,
        user,
        action="aag.connection.test",
        resource_type="aag_connection",
        resource_id=row.id,
        metadata={
            "provider": row.provider,
            "target_host": host,
            "model_name": row.model_name,
            "input_hash": entry.input_hash,
        },
    )
    return AagConnectionTestRead(
        ok=True,
        provider=row.provider,  # type: ignore[arg-type]
        host=host,
        model_name=row.model_name,
        message="Provider responds",
    )


@router.get("/calls", response_model=PaginatedResponse[AagCallLogRead])
async def list_aag_calls(
    db: AsyncSession = Depends(get_db),
    _: AuthUser = Depends(require_roles(UserRole.ADMIN)),
    page: tuple[int, int] = Depends(pagination_params),
) -> PaginatedResponse[AagCallLogRead]:
    offset, limit = page
    stmt = select(AagCallLog).order_by(AagCallLog.created_at.desc(), AagCallLog.id.desc())
    rows, total = await paginate_scalars(db, stmt, offset=offset, limit=limit)
    return PaginatedResponse(
        items=[AagCallLogRead.model_validate(item) for item in rows],
        total=total,
        offset=offset,
        limit=limit,
    )


@router.delete("/calls/{call_id}", status_code=204, response_class=Response)
async def delete_aag_call(
    call_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_roles(UserRole.ADMIN)),
) -> Response:
    row = await db.get(AagCallLog, call_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Call log entry not found")
    provider = row.provider
    target = row.target_host
    await db.delete(row)
    await db.flush()
    await log_audit_event(
        db,
        request,
        user,
        action="aag.call.delete",
        resource_type="aag_call",
        resource_id=call_id,
        metadata={"provider": provider, "target_host": target},
    )
    return Response(status_code=204)


def _stored_check_status(checks: list, rule: str, host: str) -> str:
    """Status recorded with the request. The model text does not relabel the badge."""
    for item in checks:
        if not isinstance(item, dict):
            continue
        if str(item.get("rule") or "") != rule:
            continue
        stored_host = str(item.get("host") or "")
        if host and stored_host and stored_host != host:
            continue
        status = str(item.get("status") or "").strip()
        if status:
            return status
    return ""


def artifact_to_read(row: AagArtifact) -> AagArtifactRead:
    meta = row.meta_json or {}
    paragraphs: list[AagParagraph] = []
    sections: list[AagExplainSection] = []
    host_filter = None
    rules = [str(rule) for rule in (meta.get("rules") or [])]
    stored_checks = meta.get("checks") if isinstance(meta.get("checks"), list) else []
    if row.kind == "explain" and row.response_text:
        parsed = parse_explain_sections(row.response_text)
        if parsed:
            sections = [
                AagExplainSection(
                    rule=str(item["rule"]),
                    host=str(item["host"]),
                    status=_stored_check_status(stored_checks, str(item["rule"]), str(item["host"]))
                    or str(item["status"]),
                    what=str(item["what"]),
                    checked=str(item["checked"]),
                    did=str(item["did"]),
                    confirmed=explain_section_confirmed(item, run_id=row.run_id, rules=rules),
                )
                for item in parsed
            ]
        else:
            paragraphs = [
                AagParagraph(text=item["text"], confirmed=bool(item["confirmed"]))
                for item in annotate_paragraphs(
                    row.response_text,
                    run_id=row.run_id,
                    rules=rules,
                )
            ]
    return AagArtifactRead(
        id=row.id,
        kind=row.kind,
        status=row.status,
        provider=row.provider,
        model_name=row.model_name,
        target_host=row.target_host,
        in_perimeter=row.provider == "internal",
        input_hash=row.input_hash,
        prompt_redacted=row.prompt_redacted,
        response_text=row.response_text,
        citations_json=row.citations_json,
        meta_json=row.meta_json,
        paragraphs=paragraphs,
        explain_sections=sections,
        host_filter=host_filter,
        error_message=row.error_message,
        requested_by=row.requested_by,
        created_at=row.created_at,
        finished_at=row.finished_at,
    )


@router.post("/tasks", response_model=AagArtifactRead, status_code=201)
async def create_aag_task(
    data: AagTaskCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_roles(UserRole.OPERATOR)),
) -> AagArtifactRead:
    row = await get_or_default_row(db)
    persisted = row.id is not None
    provider = row.provider if persisted else "none"
    task_submission_block(
        ai_enabled=contour_switch(
            saved=row.enabled if persisted else None,
            env_enabled=settings.ai_enabled,
        ),
        provider=provider,
        last_test_ok=row.last_test_ok if row.id is not None else None,
        demo_mode=settings.demo_mode,
    )
    artifact = await submit_aag_task(db, data, user, request, row)
    return artifact_to_read(artifact)


@router.delete("/tasks/{artifact_id}", status_code=204, response_class=Response)
async def delete_aag_task(
    artifact_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_roles(UserRole.OPERATOR)),
) -> Response:
    artifact = await delete_aag_artifact(db, user, artifact_id)
    await log_audit_event(
        db,
        request,
        user,
        action="aag.task.delete",
        resource_type="aag_artifact",
        resource_id=artifact_id,
        metadata={
            "kind": artifact.kind,
            "provider": artifact.provider,
            "target_host": artifact.target_host,
        },
    )
    return Response(status_code=204)


@router.post("/tasks/{artifact_id}/retry", response_model=AagArtifactRead)
async def retry_task(
    artifact_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_roles(UserRole.OPERATOR)),
) -> AagArtifactRead:
    row = await get_or_default_row(db)
    persisted = row.id is not None
    provider = row.provider if persisted else "none"
    task_submission_block(
        ai_enabled=contour_switch(
            saved=row.enabled if persisted else None,
            env_enabled=settings.ai_enabled,
        ),
        provider=provider,
        last_test_ok=row.last_test_ok if row.id is not None else None,
        demo_mode=settings.demo_mode,
    )
    artifact = await retry_aag_task(db, user, request, artifact_id, row)
    return artifact_to_read(artifact)


@router.get("/tasks", response_model=PaginatedResponse[AagArtifactRead])
async def list_aag_tasks(
    kind: str | None = None,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_roles(UserRole.OPERATOR, UserRole.AUDITOR)),
    page: tuple[int, int] = Depends(pagination_params),
) -> PaginatedResponse[AagArtifactRead]:
    if kind is not None and kind not in ("explain", "generate"):
        raise HTTPException(status_code=422, detail="Unknown AAG task")
    offset, limit = page
    rows, total = await list_aag_artifacts(db, user, kind=kind, offset=offset, limit=limit)
    return PaginatedResponse(
        items=[artifact_to_read(item) for item in rows],
        total=total,
        offset=offset,
        limit=limit,
    )


@router.get("/explain/candidates", response_model=list[AagExplainCandidate])
async def explain_candidates(
    run_id: int,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_roles(UserRole.OPERATOR, UserRole.AUDITOR)),
) -> list[AagExplainCandidate]:
    return await list_explain_candidates(db, user, run_id)


@router.put("/tasks/{artifact_id}/draft", response_model=AagArtifactRead)
async def save_package_draft(
    artifact_id: int,
    data: AagPackageDraft,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_roles(UserRole.OPERATOR)),
) -> AagArtifactRead:
    artifact = await update_package_draft(db, artifact_id, data, user)
    return artifact_to_read(artifact)


@router.post("/tasks/{artifact_id}/accept", response_model=AagArtifactRead)
async def accept_package(
    artifact_id: int,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_roles(UserRole.OPERATOR)),
) -> AagArtifactRead:
    artifact = await accept_generated_profile(db, artifact_id, user)
    return artifact_to_read(artifact)
