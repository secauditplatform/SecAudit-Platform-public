"""SQLAlchemy helpers for object-level RBAC in API routers."""

from __future__ import annotations

from typing import TypeVar

from fastapi import HTTPException
from sqlalchemy import Select, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm.attributes import InstrumentedAttribute

from app.core.auth import AuthUser
from app.core.config import settings
from secaudit_core.access_scope import AccessScope
from secaudit_core.enums import UserRole
from secaudit_core.object_rbac import (
    applies_engineer_scope,
    can_access_owned_resource,
    ownership_sub_for_create,
)

T = TypeVar("T")


def rbac_enabled() -> bool:
    return settings.object_rbac_enabled


def operator_scope(user: AuthUser) -> AccessScope | None:
    """Limits for an operator. Admin and auditor stay unrestricted."""
    if not rbac_enabled():
        return None
    roles = set(user.roles)
    if UserRole.ADMIN.value in roles or UserRole.AUDITOR.value in roles:
        return None
    if UserRole.OPERATOR.value not in roles:
        return None
    scope = AccessScope(tuple(user.access_sites), tuple(user.access_environments), tuple(user.access_tags))
    return scope if scope.restricted else None


def apply_host_scope(stmt: Select[tuple[T]], user: AuthUser) -> Select[tuple[T]]:
    scope = operator_scope(user)
    if scope is None:
        return stmt
    from app.models import Host, HostTag, HostTagLink

    if scope.sites:
        stmt = stmt.where(Host.site.in_(scope.sites))
    if scope.environments:
        stmt = stmt.where(Host.environment.in_(scope.environments))
    if scope.tags:
        tagged = (
            select(HostTagLink.host_id)
            .join(HostTag, HostTag.id == HostTagLink.tag_id)
            .where(HostTag.name.in_(scope.tags))
        )
        stmt = stmt.where(Host.id.in_(tagged))
    return stmt


def apply_job_scope(stmt: Select[tuple[T]], user: AuthUser) -> Select[tuple[T]]:
    """Hide a job that targets any host outside the operator's scope."""
    if operator_scope(user) is None:
        return stmt
    from app.models import Host, Job, JobHost

    visible = apply_host_scope(select(Host.id), user)
    outside = select(JobHost.job_id).where(JobHost.host_id.not_in(visible))
    return stmt.where(Job.id.not_in(outside))


def apply_audit_flow_scope(stmt: Select[tuple[T]], user: AuthUser) -> Select[tuple[T]]:
    if operator_scope(user) is None:
        return stmt
    from app.models import AuditFlowHost, AuditFlowRun, Host

    visible = apply_host_scope(select(Host.id), user)
    outside = select(AuditFlowHost.run_id).where(
        AuditFlowHost.ephemeral_host_id.is_not(None),
        AuditFlowHost.ephemeral_host_id.not_in(visible),
    )
    own_or_in_scope = or_(
        AuditFlowRun.owner_sub == user.sub,
        AuditFlowRun.id.in_(
            select(AuditFlowHost.run_id).where(AuditFlowHost.ephemeral_host_id.in_(visible))
        ),
    )
    return stmt.where(AuditFlowRun.id.not_in(outside), own_or_in_scope)


def apply_waiver_scope(stmt: Select[tuple[T]], user: AuthUser) -> Select[tuple[T]]:
    scope = operator_scope(user)
    if scope is None:
        return stmt
    from app.models import ComplianceWaiver, Host

    visible = apply_host_scope(select(Host.id), user)
    stmt = stmt.where(
        or_(ComplianceWaiver.host_id.is_(None), ComplianceWaiver.host_id.in_(visible))
    )
    if scope.sites:
        stmt = stmt.where(
            or_(ComplianceWaiver.scope_site.is_(None), ComplianceWaiver.scope_site.in_(scope.sites))
        )
    if scope.environments:
        stmt = stmt.where(
            or_(
                ComplianceWaiver.scope_environment.is_(None),
                ComplianceWaiver.scope_environment.in_(scope.environments),
            )
        )
    if scope.tags:
        stmt = stmt.where(
            or_(ComplianceWaiver.scope_tag.is_(None), ComplianceWaiver.scope_tag.in_(scope.tags))
        )
    return stmt


def apply_owner_scope(stmt: Select[tuple[T]], column: InstrumentedAttribute, user: AuthUser) -> Select[tuple[T]]:
    if applies_engineer_scope(user.roles, enabled=rbac_enabled()):
        stmt = stmt.where(column == user.sub)
    return stmt


def apply_credential_list_scope(stmt: Select[tuple[T]], user: AuthUser) -> Select[tuple[T]]:
    """Engineers see owned credentials and those linked to their hosts."""
    from app.models import Credential, Host

    if operator_scope(user) is not None:
        from app.models import Host, HostCredentialLink

        visible = apply_host_scope(select(Host.id), user)
        linked_host = select(Host.credential_id).where(
            Host.id.in_(visible),
            Host.credential_id.is_not(None),
        )
        linked_table = select(HostCredentialLink.credential_id).where(HostCredentialLink.host_id.in_(visible))
        return stmt.where(
            or_(Credential.id.in_(linked_host), Credential.id.in_(linked_table), Credential.owner_sub == user.sub)
        )

    if not applies_engineer_scope(user.roles, enabled=rbac_enabled()):
        return stmt

    shared_ids = (
        select(Host.credential_id)
        .where(Host.owner_sub == user.sub, Host.credential_id.isnot(None))
        .distinct()
    )
    return stmt.where(or_(Credential.owner_sub == user.sub, Credential.id.in_(shared_ids)))


async def assert_host_visible(db: AsyncSession, user: AuthUser, host, *, detail: str = "Host not found") -> None:
    assert_can_access(user, getattr(host, "owner_sub", None), detail=detail)
    if operator_scope(user) is None:
        return
    from app.models import Host

    found = await db.execute(apply_host_scope(select(Host.id).where(Host.id == host.id), user))
    if found.scalar_one_or_none() is None:
        raise HTTPException(status_code=404, detail=detail)


def assert_can_access(user: AuthUser, owner_sub: str | None, *, detail: str = "Not found") -> None:
    if not can_access_owned_resource(user.roles, user.sub, owner_sub, enabled=rbac_enabled()):
        raise HTTPException(status_code=404, detail=detail)


def assert_credential_attachable(user: AuthUser, owner_sub: str | None, *, detail: str = "Credential not found") -> None:
    """Engineers may attach only credentials they own; operator/admin any."""
    assert_can_access(user, owner_sub, detail=detail)


async def assert_credential_visible(db: AsyncSession, user: AuthUser, credential_id: int):
    from app.models import Credential, Host

    credential = await db.get(Credential, credential_id)
    if not credential:
        raise HTTPException(status_code=404, detail="Credential not found")

    if operator_scope(user) is not None:
        from app.models import Host, HostCredentialLink

        visible = apply_host_scope(select(Host.id), user)
        if credential.owner_sub == user.sub:
            return credential
        linked = await db.execute(
            select(Host.id)
            .where(Host.id.in_(visible), Host.credential_id == credential_id)
            .limit(1)
        )
        if linked.scalar_one_or_none() is not None:
            return credential
        linked_table = await db.execute(
            select(HostCredentialLink.host_id)
            .where(HostCredentialLink.credential_id == credential_id, HostCredentialLink.host_id.in_(visible))
            .limit(1)
        )
        if linked_table.scalar_one_or_none() is not None:
            return credential
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
    """Engineers own personal channels; admin/operator channels are platform-wide (owner_sub NULL)."""
    if not hasattr(channel, "owner_sub"):
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
    from app.services.demo_exec_targets import assert_demo_exec_host_ids

    for host_id in host_ids:
        host = await db.get(Host, host_id)
        if not host:
            raise HTTPException(status_code=404, detail=f"Host {host_id} not found")
        await assert_host_visible(db, user, host)
    await assert_demo_exec_host_ids(db, host_ids)


async def assert_job_access(db, user: AuthUser, job_id: int):
    from app.models import Job

    job = await db.get(Job, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    assert_can_access(user, job.owner_sub, detail="Job not found")
    if operator_scope(user) is not None:
        from app.models import Job

        found = await db.execute(apply_job_scope(select(Job.id).where(Job.id == job.id), user))
        if found.scalar_one_or_none() is None:
            raise HTTPException(status_code=404, detail="Job not found")
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
    if operator_scope(user) is not None:
        found = await db.execute(apply_job_scope(select(Job.id).where(Job.id == job.id), user))
        if found.scalar_one_or_none() is None:
            raise HTTPException(status_code=404, detail="Job run not found")
    return run


async def assert_audit_flow_run_access(db, user: AuthUser, run_id: int):
    from app.models import AuditFlowRun

    run = await db.get(AuditFlowRun, run_id)
    if not run:
        raise HTTPException(status_code=404, detail="AuditFlow run not found")
    assert_can_access(user, run.owner_sub, detail="AuditFlow run not found")
    if operator_scope(user) is not None:
        from app.models import AuditFlowRun

        found = await db.execute(
            apply_audit_flow_scope(select(AuditFlowRun.id).where(AuditFlowRun.id == run.id), user)
        )
        if found.scalar_one_or_none() is None:
            raise HTTPException(status_code=404, detail="AuditFlow run not found")
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
