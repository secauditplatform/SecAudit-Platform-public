#!/usr/bin/env python3
"""Seed deterministic data for Playwright E2E critical journeys."""

from __future__ import annotations

import asyncio
import os
import sys
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
API_ROOT = ROOT / "api" if (ROOT / "api").is_dir() else Path("/app")
PKG_ROOT = (
    ROOT / "packages" / "secaudit_core"
    if (ROOT / "packages" / "secaudit_core").is_dir()
    else Path("/packages/secaudit_core")
)
sys.path.insert(0, str(API_ROOT))
sys.path.insert(0, str(PKG_ROOT))

os.environ.setdefault("SKIP_MIGRATIONS", "1")

E2E_ADMIN_USERNAME = os.environ.get("E2E_ADMIN_USERNAME", "e2e-admin")
E2E_ADMIN_PASSWORD = os.environ.get("E2E_ADMIN_PASSWORD", "e2e-admin-password-32chars-min")
E2E_PROFILE_TECH = "E2E Test Profile"
E2E_HOST_NAME = "e2e-host"
E2E_JOB_NAME = "E2E Compliance Job"


async def main() -> None:
    from sqlalchemy import select

    from app.core.database import async_session
    from app.core.passwords import hash_password
    from app.models import (
        Category,
        CheckResult,
        CheckStatus,
        ExecutionType,
        Host,
        Job,
        JobHost,
        JobRun,
        JobStatus,
        Profile,
        User,
        UserRole,
    )
    from app.services.profiles import CategoryService

    async with async_session() as db:
        user_result = await db.execute(select(User).where(User.username == E2E_ADMIN_USERNAME))
        if user_result.scalar_one_or_none() is None:
            db.add(
                User(
                    username=E2E_ADMIN_USERNAME,
                    email=f"{E2E_ADMIN_USERNAME}@e2e.test",
                    hashed_password=hash_password(E2E_ADMIN_PASSWORD),
                    role=UserRole.ADMIN,
                    is_active=True,
                )
            )

        await CategoryService().seed_defaults(db)

        category = (
            await db.execute(select(Category).where(Category.slug == "linux-platform"))
        ).scalar_one()

        profile_result = await db.execute(select(Profile).where(Profile.profile_name == E2E_PROFILE_TECH))
        profile = profile_result.scalar_one_or_none()
        if profile is None:
            profile = Profile(
                profile_name=E2E_PROFILE_TECH,
                version="1.0",
                summary="Minimal profile for E2E tests",
                category_id=category.id,
                package_path="/data/profiles/e2e",
                source_format="custom",
                profile_family="custom",
                os_name="Linux",
                os_version="e2e",
                is_active=True,
            )
            db.add(profile)
            await db.flush()

        host_result = await db.execute(select(Host).where(Host.name == E2E_HOST_NAME))
        host = host_result.scalar_one_or_none()
        if host is None:
            host = Host(
                name=E2E_HOST_NAME,
                hostname="10.0.0.10",
                port=22,
                os_type="linux",
                is_active=True,
            )
            db.add(host)
            await db.flush()

        job_result = await db.execute(select(Job).where(Job.name == E2E_JOB_NAME))
        job = job_result.scalar_one_or_none()
        if job is None:
            job = Job(
                name=E2E_JOB_NAME,
                profile_id=profile.id,
                execution_type=ExecutionType.SSH,
                is_scheduled=False,
                is_active=True,
                owner_sub=f"local:{E2E_ADMIN_USERNAME}",
                enforce_host_owner_scope=False,
            )
            db.add(job)
            await db.flush()
            db.add(JobHost(job_id=job.id, host_id=host.id))
            await db.flush()

        run_result = await db.execute(
            select(JobRun).where(JobRun.job_id == job.id).order_by(JobRun.id.desc())
        )
        run = run_result.scalars().first()
        if run is None:
            now = datetime.now(UTC)
            run = JobRun(
                job_id=job.id,
                status=JobStatus.COMPLETED,
                started_at=now,
                finished_at=now,
            )
            db.add(run)
            await db.flush()
            db.add(
                CheckResult(
                    job_run_id=run.id,
                    host_id=host.id,
                    rule_tech_name="e2e.check.pass",
                    status=CheckStatus.PASS,
                    message="E2E seeded check",
                )
            )
            db.add(
                CheckResult(
                    job_run_id=run.id,
                    host_id=host.id,
                    rule_tech_name="e2e.check.fail",
                    status=CheckStatus.FAIL,
                    message="E2E seeded failure",
                )
            )

        await db.commit()
        print(
            f"E2E seed OK: user={E2E_ADMIN_USERNAME}, profile={profile.id}, "
            f"host={host.id}, job={job.id}, run={run.id if run else 'n/a'}"
        )


if __name__ == "__main__":
    asyncio.run(main())
