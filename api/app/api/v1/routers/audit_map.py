from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import AuthUser
from app.core.database import get_db
from app.core.roles import require_operate, require_reports
from app.schemas.audit_map import (
    AuditMapEdgeRead,
    AuditMapEdgeWrite,
    AuditMapRead,
    AuditMapServiceRead,
    AuditMapServiceWrite,
)
from app.services.audit_map import (
    build_audit_map,
    confirm_service,
    create_edge,
    delete_edge,
    delete_service,
    site_query,
)
from secaudit_core.audit_map import protocol_for_port

router = APIRouter()


@router.get("", response_model=AuditMapRead)
async def get_audit_map(
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_reports),
    site: str | None = Query(default=None),
    environment: str | None = Query(default=None),
    criticality: str | None = Query(default=None),
    tag: str | None = Query(default=None),
    profile: str | None = Query(default=None),
) -> dict:
    return await build_audit_map(
        db,
        user,
        site=site_query(site),
        environment=environment,
        criticality=criticality,
        tag=tag,
        profile=profile,
    )


@router.post("/services", response_model=AuditMapServiceRead)
async def post_audit_map_service(
    body: AuditMapServiceWrite,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_operate),
) -> dict:
    row = await confirm_service(db, user, body.host_id, body.port)
    return {
        "id": row.id,
        "port": row.port,
        "protocol": protocol_for_port(row.port),
        "source": "manual",
        "confirmed": True,
        "status": "unchecked",
        "coverage_reason": None,
    }


@router.delete("/services/{service_id}", status_code=204)
async def delete_audit_map_service(
    service_id: int,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_operate),
) -> None:
    await delete_service(db, user, service_id)


@router.post("/edges", response_model=AuditMapEdgeRead)
async def post_audit_map_edge(
    body: AuditMapEdgeWrite,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_operate),
) -> dict:
    row = await create_edge(db, user, body.model_dump())
    return {
        "id": row.id,
        "source_host_id": row.source_host_id,
        "source_port": row.source_port,
        "target_host_id": row.target_host_id,
        "target_port": row.target_port,
    }


@router.delete("/edges/{edge_id}", status_code=204)
async def delete_audit_map_edge(
    edge_id: int,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_operate),
) -> None:
    await delete_edge(db, user, edge_id)
