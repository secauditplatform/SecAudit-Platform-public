"""Run one AAG artifact. The only argument is the artifact id.

The external key is decrypted here and is not written back onto the artifact,
the call journal, or the error text.
"""

from __future__ import annotations

import os
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker

from secaudit_core.aag_client import (
    DRAFT_TYPES,
    AagClientError,
    apply_operator_profile,
    complete_chat,
    generated_package_files,
    package_request_errors,
    token_limit,
    write_generated_package,
)
from secaudit_core.models import AagArtifact, AagCallLog, AagProviderConfig
from secaudit_core.secrets import decrypt_secret
from secaudit_core.sensitive_data import REDACTED
from secaudit_core.settings import SecAuditSettings


def _demo_mode(settings: SecAuditSettings) -> bool:
    value = getattr(settings, "demo_mode", None)
    if isinstance(value, bool):
        return value
    return os.environ.get("DEMO_MODE", "").strip().lower() in {"1", "true", "yes", "on"}


def _journal(
    db: Session,
    artifact: AagArtifact,
    row: AagProviderConfig | None,
    *,
    outcome: str,
    error_code: str | None = None,
    duration_ms: int | None = None,
    token_count: int | None = None,
) -> None:
    """One journal row. The code is a short token, never the prompt or the key."""
    provider = (row.provider if row is not None else "") or "none"
    meta = artifact.meta_json or {}
    draft = meta.get("draft_type") if artifact.kind == "draft" else None
    if draft not in DRAFT_TYPES:
        draft = None
    code = "".join(ch for ch in (error_code or "") if ch.isalnum() or ch == "_")[:32] or None
    db.add(
        AagCallLog(
            provider=provider[:16],
            target_host=artifact.target_host,
            model_name=(row.model_name if row is not None else None) or artifact.model_name,
            input_hash=artifact.input_hash,
            kind=artifact.kind,
            draft_type=draft,
            outcome=outcome,
            error_code=code,
            duration_ms=duration_ms,
            run_id=artifact.run_id,
            in_perimeter=provider == "internal",
            token_count=token_count if isinstance(token_count, int) and token_count >= 0 else None,
            created_by=artifact.requested_by,
        )
    )


def _fail(
    db: Session,
    artifact: AagArtifact,
    message: str,
    *,
    row: AagProviderConfig | None = None,
    error_code: str,
    duration_ms: int | None = None,
    status: str = "failed",
) -> None:
    artifact.status = status
    artifact.error_message = message[:500]
    artifact.finished_at = datetime.now(UTC)
    _journal(db, artifact, row, outcome=status if status == "cancelled" else "failed", error_code=error_code, duration_ms=duration_ms)
    db.commit()


def _scrub(message: str, api_key: str | None) -> str:
    text = message
    if api_key:
        text = text.replace(api_key, REDACTED)
    return text[:500]


def _is_cancelled(db: Session, artifact_id: int) -> bool:
    db.expire_all()
    status = db.execute(select(AagArtifact.status).where(AagArtifact.id == artifact_id)).scalar_one_or_none()
    return status == "cancelled"


def run_aag_artifact(artifact_id: int, *, database_url: str, settings: SecAuditSettings) -> None:
    engine = create_engine(database_url)
    session_local = sessionmaker(bind=engine)
    with session_local() as db:
        artifact = db.get(AagArtifact, artifact_id)
        if artifact is None or artifact.status not in ("pending", "running"):
            return
        if artifact.status == "cancelled":
            return
        row = db.execute(
            select(AagProviderConfig).where(AagProviderConfig.selected.is_(True)).limit(1)
        ).scalars().first()
        if artifact.kind in ("brief", "draft", "search"):
            _fail(db, artifact, "This section is no longer available", row=row, error_code="removed")
            return
        if row is None or not row.enabled or row.provider in ("", "none"):
            _fail(db, artifact, "AAG is disabled", row=row, error_code="disabled")
            return
        if row.provider == "external" and _demo_mode(settings):
            _fail(db, artifact, "External AI API is disabled in demo mode", row=row, error_code="demo")
            return
        if row.last_test_ok is False:
            _fail(db, artifact, "Provider does not respond", row=row, error_code="unreachable")
            return
        base_url = row.external_base_url if row.provider == "external" else row.internal_base_url
        api_key: str | None = None
        if row.provider == "external":
            if not row.encrypted_external_key:
                _fail(db, artifact, "External provider has no API key", row=row, error_code="no_key")
                return
            try:
                api_key = decrypt_secret(row.encrypted_external_key, settings)
            except Exception:
                _fail(db, artifact, "Stored API key could not be read", row=row, error_code="key_unreadable")
                return
        artifact.status = "running"
        meta = dict(artifact.meta_json or {})
        meta["stream_chars"] = 0
        artifact.meta_json = meta
        db.commit()

        stream_chars = 0
        last_progress = 0.0

        def should_cancel() -> bool:
            return _is_cancelled(db, artifact_id)

        def on_delta(piece: str) -> None:
            nonlocal stream_chars, last_progress
            stream_chars += len(piece)
            now = time.monotonic()
            if now - last_progress < 2.0:
                return
            last_progress = now
            if _is_cancelled(db, artifact_id):
                return
            current = db.get(AagArtifact, artifact_id)
            if current is None or current.status == "cancelled":
                return
            progress = dict(current.meta_json or {})
            progress["stream_chars"] = stream_chars
            current.meta_json = progress
            db.commit()

        started = time.perf_counter()
        try:
            result = complete_chat(
                provider=row.provider,
                base_url=base_url or "",
                model=row.model_name or artifact.model_name or "",
                fragment=artifact.prompt_redacted,
                kind=artifact.kind,
                api_key=api_key,
                timeout_seconds=row.timeout_seconds or settings.ai_timeout_seconds,
                idle_read_timeout_seconds=getattr(
                    settings, "ai_idle_read_timeout_seconds", 90
                ),
                max_tokens=token_limit(artifact.kind, row.max_tokens or settings.ai_max_tokens),
                retry_on_network_error=settings.ai_retry_on_network_error,
                allow_private=settings.outbound_webhooks_allow_private,
                citation=artifact.citations_json,
                should_cancel=should_cancel,
                on_delta=on_delta,
            )
        except AagClientError as exc:
            elapsed = int((time.perf_counter() - started) * 1000)
            if exc.error_code == "cancelled" or _is_cancelled(db, artifact_id):
                current = db.get(AagArtifact, artifact_id)
                if current is not None:
                    _fail(
                        db,
                        current,
                        "Task cancelled",
                        row=row,
                        error_code="cancelled",
                        duration_ms=elapsed,
                        status="cancelled",
                    )
                return
            current = db.get(AagArtifact, artifact_id)
            if current is None or current.status == "cancelled":
                return
            _fail(
                db,
                current,
                _scrub(str(exc), api_key),
                row=row,
                error_code=exc.error_code or "request",
                duration_ms=elapsed,
            )
            return
        except Exception as exc:
            elapsed = int((time.perf_counter() - started) * 1000)
            if _is_cancelled(db, artifact_id):
                current = db.get(AagArtifact, artifact_id)
                if current is not None:
                    _fail(
                        db,
                        current,
                        "Task cancelled",
                        row=row,
                        error_code="cancelled",
                        duration_ms=elapsed,
                        status="cancelled",
                    )
                return
            current = db.get(AagArtifact, artifact_id)
            if current is None or current.status == "cancelled":
                return
            _fail(
                db,
                current,
                _scrub(str(exc), api_key),
                row=row,
                error_code="request",
                duration_ms=elapsed,
            )
            return
        if _is_cancelled(db, artifact_id):
            current = db.get(AagArtifact, artifact_id)
            if current is not None:
                _fail(
                    db,
                    current,
                    "Task cancelled",
                    row=row,
                    error_code="cancelled",
                    duration_ms=int((time.perf_counter() - started) * 1000),
                    status="cancelled",
                )
            return
        elapsed = int((time.perf_counter() - started) * 1000)
        artifact = db.get(AagArtifact, artifact_id)
        if artifact is None:
            return
        text = result.text
        artifact.status = "completed"
        artifact.response_text = text
        artifact.finished_at = datetime.now(UTC)
        meta = dict(artifact.meta_json or {})
        meta.pop("stream_chars", None)
        if artifact.kind == "generate":
            files = generated_package_files(text, profile_name=str(meta.get("profile_name") or ""))
            profile = meta.get("profile")
            if isinstance(profile, dict):
                files = apply_operator_profile(files, profile)
            errors = package_request_errors(files)
            if not errors:
                with tempfile.TemporaryDirectory() as directory:
                    errors = write_generated_package(files, Path(directory))
            if errors:
                artifact.status = "failed"
                artifact.response_text = None
                artifact.error_message = "; ".join(errors)[:500]
                artifact.finished_at = datetime.now(UTC)
                meta["validation_errors"] = errors
                artifact.meta_json = meta
                _journal(
                    db,
                    artifact,
                    row,
                    outcome="failed",
                    error_code="invalid_package",
                    duration_ms=elapsed,
                    token_count=result.token_count,
                )
                db.commit()
                return
            meta["files"] = files
            meta["validation_errors"] = []
        artifact.meta_json = meta
        _journal(
            db,
            artifact,
            row,
            outcome="ok",
            duration_ms=elapsed,
            token_count=result.token_count,
        )
        db.commit()
