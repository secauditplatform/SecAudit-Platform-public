"""Network config upload and remediation config download."""

from __future__ import annotations

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from fastapi.responses import PlainTextResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import AuthUser, require_roles
from app.core.roles import require_operate, require_remediation
from app.core.database import get_db
from app.models import Job, JobScope, NetworkDeviceConfig, NetworkRemediationConfig, RemediationJob, RemediationRun, UserRole
from app.schemas import NetworkDeviceConfigRead, NetworkRemediationConfigGenerate, NetworkRemediationConfigRead
from app.services.object_rbac import assert_can_access
from secaudit_core.enums import NetworkVendor
from secaudit_core.network_config import generate_remediation_config
from secaudit_core.network_scope import infer_vendor_from_filename

router = APIRouter()


@router.get("/jobs/{job_id}/configs", response_model=list[NetworkDeviceConfigRead])
async def list_network_configs(
    job_id: int,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_operate),
) -> list[NetworkDeviceConfigRead]:
    job = await db.get(Job, job_id)
    if not job or job.scope != JobScope.NETWORK:
        raise HTTPException(status_code=404, detail="Network job not found")
    assert_can_access(user, job.owner_sub)
    result = await db.execute(
        select(NetworkDeviceConfig)
        .where(NetworkDeviceConfig.job_id == job_id)
        .order_by(NetworkDeviceConfig.id.desc())
    )
    return [NetworkDeviceConfigRead.model_validate(row) for row in result.scalars().all()]


@router.post("/jobs/{job_id}/configs/upload", response_model=NetworkDeviceConfigRead, status_code=201)
async def upload_network_config(
    job_id: int,
    host_id: int | None = Form(default=None),
    vendor: NetworkVendor | None = Form(default=None),
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_roles(UserRole.OPERATOR, UserRole.ADMIN)),
) -> NetworkDeviceConfigRead:
    job = await db.get(Job, job_id)
    if not job or job.scope != JobScope.NETWORK:
        raise HTTPException(status_code=404, detail="Network job not found")
    assert_can_access(user, job.owner_sub)

    raw = await file.read()
    if len(raw) > 5 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="Config file exceeds 5 MiB limit")
    try:
        content = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise HTTPException(status_code=400, detail="Config file must be UTF-8 text") from exc

    filename = file.filename or "config.txt"
    resolved_vendor = vendor or infer_vendor_from_filename(filename)
    row = NetworkDeviceConfig(
        job_id=job_id,
        host_id=host_id,
        vendor=resolved_vendor,
        filename=filename,
        content=content,
        owner_sub=user.sub,
    )
    db.add(row)
    await db.commit()
    await db.refresh(row)
    return NetworkDeviceConfigRead.model_validate(row)


@router.get("/remediations/runs/{run_id}/configs/{config_id}/download")
async def download_remediation_config(
    run_id: int,
    config_id: int,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_remediation),
) -> PlainTextResponse:
    result = await db.execute(
        select(NetworkRemediationConfig).where(
            NetworkRemediationConfig.id == config_id,
            NetworkRemediationConfig.remediation_run_id == run_id,
        )
    )
    row = result.scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="Remediation config not found")

    run = await db.get(RemediationRun, run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Remediation run not found")
    job = await db.get(RemediationJob, run.remediation_job_id)
    if job:
        assert_can_access(user, job.owner_sub)

    return PlainTextResponse(
        content=row.content,
        headers={"Content-Disposition": f'attachment; filename="{row.filename}"'},
    )


@router.post(
    "/remediations/runs/{run_id}/configs/generate",
    response_model=NetworkRemediationConfigRead,
    status_code=201,
)
async def generate_network_remediation_config(
    run_id: int,
    data: NetworkRemediationConfigGenerate,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_remediation),
) -> NetworkRemediationConfigRead:
    run = await db.get(RemediationRun, run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Remediation run not found")
    job = await db.get(RemediationJob, run.remediation_job_id)
    if not job or job.scope != JobScope.NETWORK:
        raise HTTPException(status_code=400, detail="Not a network remediation run")
    assert_can_access(user, job.owner_sub)

    content = data.content.strip()
    if not content:
        content = generate_remediation_config(
            data.vendor,
            hostname=data.hostname,
            commands=data.commands,
        )
    filename = data.filename or f"remediation-{run_id}-{data.vendor.value}.cfg"
    row = NetworkRemediationConfig(
        remediation_run_id=run_id,
        host_id=data.host_id,
        vendor=data.vendor,
        filename=filename,
        content=content,
    )
    db.add(row)
    await db.commit()
    await db.refresh(row)
    return NetworkRemediationConfigRead.model_validate(row)
