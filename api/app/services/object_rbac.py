"""SQLAlchemy helpers for object-level RBAC in API routers."""

from __future__ import annotations

from typing import TypeVar

from fastapi import HTTPException
from sqlalchemy import Select, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm.attributes import InstrumentedAttribute

from app.core.auth import AuthUser
from app.core.config import settings
from secaudit_core.enums import UserRole
from secaudit_core.object_rbac import (
    applies_engineer_scope,
    can_access_owned_resource,
    ownership_sub_for_create,
)

T = TypeVar("T")


def rbac_enabled() -> bool:
    return settings.object_rbac_enabled


def apply_owner_scope(stmt: Select[tuple[T]], column: InstrumentedAttribute, user: AuthUser) -> Select[tuple[T]]:
    if applies_engineer_scope(user.roles, enabled=rbac_enabled()):
        # Own rows + platform-shared (owner_sub IS NULL).
        stmt = stmt.where(or_(column == user.sub, column.is_(None)))
    return stmt


def apply_credential_list_scope(stmt: Select[tuple[T]], user: AuthUser) -> Select[tuple[T]]:
    """Engineers see owned credentials and those linked to their hosts."""
    from app.models import Credential, Host

    if not applies_engineer_scope(user.roles, enabled=rbac_enabled()):
        return stmt

    shared_ids = (
        select(Host.credential_id)
        .where(Host.owner_sub == user.sub, Host.credential_id.isnot(None))
        .distinct()
    )
    return stmt.where(or_(Credential.owner_sub == user.sub, Credential.id.in_(shared_ids)))


def assert_can_access(
    user: AuthUser,
    owner_sub: str | None,
    *,
    detail: str = "Not found",
    mutate: bool = False,
) -> None:
    if not can_access_owned_resource(
        user.roles,
        user.sub,
        owner_sub,
        enabled=rbac_enabled(),
        mutate=mutate,
    ):
        raise HTTPException(status_code=404, detail=detail)


def assert_can_mutate(user: AuthUser, owner_sub: str | None, *, detail: str = "Not found") -> None:
    assert_can_access(user, owner_sub, detail=detail, mutate=True)


def assert_credential_attachable(user: AuthUser, owner_sub: str | None, *, detail: str = "Credential not found") -> None:
    """Engineers may attach only credentials they own; operator/admin any."""
    assert_can_access(user, owner_sub, detail=detail)


async def assert_credential_visible(db: AsyncSession, user: AuthUser, credential_id: int):
    from app.models import Credential, Host

    credential = await db.get(Credential, credential_id)
    if not credential:
        raise HTTPException(status_code=404, detail="Credential not found")

    if not applies_engineer_scope(user.roles, enabled=rbac_enabled()):
        return credential

    if credential.owner_sub == user.sub:
        return credential

    linked = await db.execute(
        select(Host.id)
        .where(Host.credential_id == credential_id, Host.owner_sub == user.sub)
        .limit(1)
    )
    if linked.scalar_one_or_none() is not None:
        return credential

    raise HTTPException(status_code=404, detail="Credential not found")


def assign_owner(obj: object, user: AuthUser) -> None:
    if hasattr(obj, "owner_sub"):
        obj.owner_sub = ownership_sub_for_create(user.sub)  # type: ignore[attr-defined]


def assign_notification_channel_owner(channel: object, user: AuthUser) -> None:
    """Admins create platform-wide channels (owner_sub NULL); others own personal channels."""
    if not hasattr(channel, "owner_sub"):
        return
    if UserRole.ADMIN.value in set(user.roles):
        channel.owner_sub = None  # type: ignore[attr-defined]
        return
    if applies_engineer_scope(user.roles, enabled=rbac_enabled()):
        channel.owner_sub = ownership_sub_for_create(user.sub)  # type: ignore[attr-defined]



def assign_host_target_scope(obj: object, user: AuthUser) -> None:
    """Persist whether dynamic host targeting must stay within the job owner."""
    if hasattr(obj, "enforce_host_owner_scope"):
        obj.enforce_host_owner_scope = applies_engineer_scope(  # type: ignore[attr-defined]
            user.roles,
            enabled=rbac_enabled(),
        )


async def assert_hosts_accessible(db, user: AuthUser, host_ids: list[int]) -> None:
    from app.models import Host

    for host_id in host_ids:
        host = await db.get(Host, host_id)
        if not host:
            raise HTTPException(status_code=404, detail=f"Host {host_id} not found")
        assert_can_access(user, host.owner_sub, detail="Host not found")


async def assert_job_access(db, user: AuthUser, job_id: int):
    from app.models import Job

    job = await db.get(Job, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    assert_can_access(user, job.owner_sub, detail="Job not found")
    return job


async def assert_job_run_access(db, user: AuthUser, run_id: int):
    from app.models import Job, JobRun

    run = await db.get(JobRun, run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Job run not found")
    job = await db.get(Job, run.job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job run not found")
    assert_can_access(user, job.owner_sub, detail="Job run not found")
    return run


async def assert_audit_flow_run_access(db, user: AuthUser, run_id: int):
    from app.models import AuditFlowRun

    run = await db.get(AuditFlowRun, run_id)
    if not run:
        raise HTTPException(status_code=404, detail="AuditFlow run not found")
    assert_can_access(user, run.owner_sub, detail="AuditFlow run not found")
    return run


async def assert_remediation_run_access(db, user: AuthUser, run_id: int):
    from app.models import RemediationJob, RemediationRun

    run = await db.get(RemediationRun, run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Remediation run not found")
    job = await db.get(RemediationJob, run.remediation_job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Remediation run not found")
    assert_can_access(user, job.owner_sub, detail="Remediation run not found")
    return run
