"""Build large report packs asynchronously into ReportArtifact files."""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from pathlib import Path

from app.celery_app import celery_app
from app.tasks.compliance import SessionLocal
from secaudit_core.models import ReportArtifact
from secaudit_core.report_pack import materialize_run_pack
from secaudit_core.settings import SecAuditSettings

logger = logging.getLogger(__name__)


@celery_app.task(name="app.tasks.report_artifacts.build_report_pack")
def build_report_pack(artifact_id: int) -> dict:
    settings = SecAuditSettings()
    root = Path(settings.report_artifacts_path)
    root.mkdir(parents=True, exist_ok=True)

    with SessionLocal() as db:
        artifact = db.get(ReportArtifact, artifact_id)
        if artifact is None:
            return {"ok": False, "reason": "missing"}
        if artifact.status == "ready" and artifact.file_path:
            return {"ok": True, "path": artifact.file_path, "cached": True}

        artifact.status = "running"
        artifact.error_message = None
        db.commit()

        try:
            pack_bytes = materialize_run_pack(db, artifact.job_run_id, locale=artifact.locale or "en")
            out_path = root / f"pack-{artifact.job_run_id}-{artifact.id}.zip"
            out_path.write_bytes(pack_bytes)
            artifact.file_path = str(out_path)
            artifact.status = "ready"
            artifact.finished_at = datetime.now(UTC)
            db.commit()
            return {"ok": True, "path": artifact.file_path}
        except Exception as exc:
            logger.exception("Report pack artifact %s failed", artifact_id)
            artifact.status = "failed"
            artifact.error_message = str(exc)[:2000]
            artifact.finished_at = datetime.now(UTC)
            db.commit()
            return {"ok": False, "error": str(exc)[:500]}
