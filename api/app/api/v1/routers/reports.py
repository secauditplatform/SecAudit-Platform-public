from datetime import date
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import AuthUser, require_roles
from app.core.roles import require_reports
from app.core.blocking import run_blocking
from app.core.config import settings
from app.core.database import get_db
from app.models import ReportArtifact, UserRole
from app.schemas import (
    ComplianceOpsOverview,
    ComplianceTimelinePoint,
    DiffReport,
    DriftReport,
    HostCompliancePoint,
    JobBaselineRead,
    JobBaselineSet,
    MultiRunCompareReport,
    RemediationSuggestion,
    ReportArtifactRead,
    ReportSummary,
    ProfileCompliancePoint,
)
from secaudit_core.celery_dispatch import send_task
from secaudit_core.reports import REPORT_PACK_ASYNC_THRESHOLD
from app.services.drift import (
    clear_job_baseline,
    fetch_diff_report,
    fetch_drift_report,
    get_job_baseline_run_id,
    set_job_baseline,
)
from app.services.object_rbac import assert_job_access, assert_job_run_access
from app.services.remediation_workflow import build_remediation_suggestion
from app.services.report_ux import (
    build_run_package_zip,
    fetch_multi_run_compare,
    fetch_run_csv,
    fetch_run_sarif,
    fetch_run_xlsx,
    load_run_evidence,
    render_multi_compare_csv,
)
from app.services.reports import (
    count_run_checks,
    fetch_run_report_context,
    fetch_run_summary,
    render_run_report_html,
    render_run_report_pdf,
    waived_check_ids_for_job_run,
)
from secaudit_core.report_i18n import resolve_report_locale
from app.services.trends import (
    fetch_compliance_by_host,
    fetch_compliance_by_profile,
    fetch_compliance_ops_overview,
    fetch_compliance_timeline,
)

router = APIRouter()


def _report_locale(locale: str | None, request: Request) -> str:
    return resolve_report_locale(locale, accept_language=request.headers.get("accept-language"))


@router.get("/trends/compliance", response_model=list[ComplianceTimelinePoint])
async def get_compliance_timeline(
    job_id: int | None = None,
    profile_id: int | None = None,
    days: int = 30,
    date_from: date | None = None,
    date_to: date | None = None,
    limit: int = 50,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_reports),
) -> list[ComplianceTimelinePoint]:
    if job_id is not None:
        await assert_job_access(db, user, job_id)
    return await fetch_compliance_timeline(
        db, job_id, profile_id, days=days, limit=limit, user=user, date_from=date_from, date_to=date_to
    )


@router.get("/trends/by-host", response_model=list[HostCompliancePoint])
async def get_compliance_by_host(
    run_id: int,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_reports),
) -> list[HostCompliancePoint]:
    await assert_job_run_access(db, user, run_id)
    return await fetch_compliance_by_host(db, run_id)


@router.get("/trends/by-profile", response_model=list[ProfileCompliancePoint])
async def get_compliance_by_profile(
    days: int = 30,
    date_from: date | None = None,
    date_to: date | None = None,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_reports),
) -> list[ProfileCompliancePoint]:
    return await fetch_compliance_by_profile(db, days=days, user=user, date_from=date_from, date_to=date_to)


@router.get("/trends/operations", response_model=ComplianceOpsOverview)
async def get_compliance_operations(
    days: int = 30,
    date_from: date | None = None,
    date_to: date | None = None,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_reports),
) -> ComplianceOpsOverview:
    return await fetch_compliance_ops_overview(
        db, days=days, user=user, date_from=date_from, date_to=date_to
    )


@router.get("/runs/{run_id}/remediation-suggestions", response_model=RemediationSuggestion)
async def get_run_remediation_suggestions(
    run_id: int,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_reports),
) -> RemediationSuggestion:
    data = await build_remediation_suggestion(db, user, run_id)
    return RemediationSuggestion(**data)


@router.get("/runs/{run_id}/summary", response_model=ReportSummary)
async def get_run_summary(
    run_id: int,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_reports),
) -> ReportSummary:
    await assert_job_run_access(db, user, run_id)
    return await fetch_run_summary(db, run_id)


@router.get("/runs/{run_id}/report.html", response_class=HTMLResponse)
async def get_run_report_html(
    run_id: int,
    request: Request,
    locale: str | None = Query(default=None, description="UI locale for report labels"),
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_reports),
) -> HTMLResponse:
    await assert_job_run_access(db, user, run_id)
    context = await fetch_run_report_context(db, run_id)
    if not context:
        raise HTTPException(status_code=404, detail="Job run not found")
    job_run, profile, hosts = context
    waived_ids = await waived_check_ids_for_job_run(db, job_run)
    html = render_run_report_html(
        job_run,
        profile,
        hosts,
        locale=_report_locale(locale, request),
        waived_check_ids=waived_ids,
    )
    return HTMLResponse(content=html)


@router.get("/runs/{run_id}/drift", response_model=DriftReport)
async def get_run_drift(
    run_id: int,
    baseline_run_id: int,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_reports),
) -> DriftReport:
    await assert_job_run_access(db, user, run_id)
    await assert_job_run_access(db, user, baseline_run_id)
    return await fetch_drift_report(db, run_id, baseline_run_id)


@router.get("/diff", response_model=DiffReport)
async def get_runs_diff(
    left_run_id: int,
    right_run_id: int,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_reports),
) -> DiffReport:
    """Run comparison for two runs (left = A, right = B). Reuses drift pairing."""
    await assert_job_run_access(db, user, left_run_id)
    await assert_job_run_access(db, user, right_run_id)
    return await fetch_diff_report(db, left_run_id, right_run_id)


@router.get("/compare", response_model=MultiRunCompareReport)
async def get_runs_compare(
    run_ids: str = Query(..., description="Comma-separated run IDs (2–8), same job"),
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_reports),
) -> MultiRunCompareReport:
    parsed: list[int] = []
    for part in run_ids.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            parsed.append(int(part))
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=f"Invalid run id: {part}") from exc
    for run_id in parsed:
        await assert_job_run_access(db, user, run_id)
    return await fetch_multi_run_compare(db, parsed)


@router.get("/compare.csv")
async def get_runs_compare_csv(
    run_ids: str = Query(..., description="Comma-separated run IDs (2–8), same job"),
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_reports),
) -> Response:
    parsed: list[int] = []
    for part in run_ids.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            parsed.append(int(part))
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=f"Invalid run id: {part}") from exc
    for run_id in parsed:
        await assert_job_run_access(db, user, run_id)
    report = await fetch_multi_run_compare(db, parsed)
    content = render_multi_compare_csv(report)
    joined = "-".join(str(run_id) for run_id in report.run_ids)
    return Response(
        content=content,
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="compare-{joined}.csv"'},
    )


@router.get("/jobs/{job_id}/baseline", response_model=JobBaselineRead)
async def get_job_baseline(
    job_id: int,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_reports),
) -> JobBaselineRead:
    await assert_job_access(db, user, job_id)
    baseline_run_id = await get_job_baseline_run_id(db, job_id)
    return JobBaselineRead(baseline_run_id=baseline_run_id)


@router.put("/jobs/{job_id}/baseline", response_model=JobBaselineRead)
async def put_job_baseline(
    job_id: int,
    data: JobBaselineSet,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_roles(UserRole.OPERATOR, UserRole.ADMIN)),
) -> JobBaselineRead:
    await assert_job_access(db, user, job_id)
    await assert_job_run_access(db, user, data.run_id)
    baseline_run_id = await set_job_baseline(db, job_id, data.run_id)
    return JobBaselineRead(baseline_run_id=baseline_run_id)


@router.delete("/jobs/{job_id}/baseline", status_code=204)
async def delete_job_baseline(
    job_id: int,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_roles(UserRole.OPERATOR, UserRole.ADMIN)),
) -> None:
    await assert_job_access(db, user, job_id)
    await clear_job_baseline(db, job_id)


@router.get("/runs/{run_id}/report.pdf")
async def get_run_report_pdf(
    run_id: int,
    request: Request,
    locale: str | None = Query(default=None, description="UI locale for report labels"),
    mode: str = Query(default="executive", description="executive|full"),
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_reports),
) -> Response:
    await assert_job_run_access(db, user, run_id)
    context = await fetch_run_report_context(db, run_id)
    if not context:
        raise HTTPException(status_code=404, detail="Job run not found")
    job_run, profile, hosts = context
    resolved_locale = _report_locale(locale, request)
    waived_ids = await waived_check_ids_for_job_run(db, job_run)
    executive = (mode or "executive").strip().lower() != "full"

    try:
        pdf_bytes = await run_blocking(
            render_run_report_pdf,
            job_run,
            profile,
            hosts,
            locale=resolved_locale,
            waived_check_ids=waived_ids,
            executive=executive,
            timeout=settings.blocking_io_timeout_seconds,
        )
    except TimeoutError as exc:
        raise HTTPException(status_code=504, detail="PDF rendering timed out") from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    suffix = "executive" if executive else "full"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="report-{run_id}-{suffix}.pdf"'},
    )


@router.get("/runs/{run_id}/report.csv")
async def get_run_report_csv(
    run_id: int,
    status: str | None = None,
    severity: str | None = None,
    host_id: int | None = None,
    rule: str | None = None,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_reports),
) -> Response:
    await assert_job_run_access(db, user, run_id)
    content, filename = await fetch_run_csv(
        db,
        run_id,
        status=status,
        severity=severity,
        host_id=host_id,
        rule=rule,
    )
    return Response(
        content=content,
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/runs/{run_id}/report.sarif")
async def get_run_report_sarif(
    run_id: int,
    status: str | None = None,
    severity: str | None = None,
    host_id: int | None = None,
    rule: str | None = None,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_reports),
) -> Response:
    await assert_job_run_access(db, user, run_id)
    content, filename = await fetch_run_sarif(
        db,
        run_id,
        tool_version=settings.app_version,
        status=status,
        severity=severity,
        host_id=host_id,
        rule=rule,
    )
    return Response(
        content=content,
        media_type="application/sarif+json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/runs/{run_id}/report.xlsx")
async def get_run_report_xlsx(
    run_id: int,
    status: str | None = None,
    severity: str | None = None,
    host_id: int | None = None,
    rule: str | None = None,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_reports),
) -> Response:
    await assert_job_run_access(db, user, run_id)
    content, filename = await fetch_run_xlsx(
        db,
        run_id,
        status=status,
        severity=severity,
        host_id=host_id,
        rule=rule,
    )
    return Response(
        content=content,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


def _artifact_read(row: ReportArtifact) -> ReportArtifactRead:
    return ReportArtifactRead(
        id=row.id,
        job_run_id=row.job_run_id,
        kind=row.kind,
        mode=row.mode,
        locale=row.locale,
        status=row.status,
        error_message=row.error_message,
        created_at=row.created_at,
        finished_at=row.finished_at,
    )


@router.get("/runs/{run_id}/report.pack.zip")
async def get_run_report_pack(
    run_id: int,
    request: Request,
    locale: str | None = Query(default=None, description="UI locale for report labels"),
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_reports),
) -> Response:
    """Download HTML+executive PDF+CSV+evidence ZIP; large runs return 202 + artifact id."""
    await assert_job_run_access(db, user, run_id)
    resolved_locale = _report_locale(locale, request)
    threshold = getattr(settings, "report_pack_async_threshold", None) or REPORT_PACK_ASYNC_THRESHOLD
    check_count = await count_run_checks(db, run_id)

    if check_count >= threshold:
        existing = (
            await db.execute(
                select(ReportArtifact)
                .where(
                    ReportArtifact.job_run_id == run_id,
                    ReportArtifact.kind == "pack",
                    ReportArtifact.locale == resolved_locale,
                    ReportArtifact.status.in_(("pending", "running", "ready")),
                )
                .order_by(ReportArtifact.id.desc())
                .limit(1)
            )
        ).scalar_one_or_none()
        if existing is not None and existing.status == "ready" and existing.file_path:
            path = Path(existing.file_path)
            if path.is_file():
                return Response(
                    content=path.read_bytes(),
                    media_type="application/zip",
                    headers={"Content-Disposition": f'attachment; filename="report-{run_id}-pack.zip"'},
                )
        if existing is not None and existing.status in ("pending", "running"):
            return JSONResponse(status_code=202, content=_artifact_read(existing).model_dump(mode="json"))

        artifact = ReportArtifact(
            job_run_id=run_id,
            kind="pack",
            mode="executive",
            locale=resolved_locale,
            status="pending",
        )
        db.add(artifact)
        await db.commit()
        await db.refresh(artifact)
        send_task(
            "app.tasks.report_artifacts.build_report_pack",
            [artifact.id],
            broker_url=settings.celery_broker_url_effective,
            queue="maintenance",
        )
        return JSONResponse(status_code=202, content=_artifact_read(artifact).model_dump(mode="json"))

    context = await fetch_run_report_context(db, run_id)
    if not context:
        raise HTTPException(status_code=404, detail="Job run not found")
    job_run, profile, hosts = context
    waived_ids = await waived_check_ids_for_job_run(db, job_run)
    html = render_run_report_html(
        job_run,
        profile,
        hosts,
        locale=resolved_locale,
        waived_check_ids=waived_ids,
        executive=False,
    )
    try:
        pdf_bytes = await run_blocking(
            render_run_report_pdf,
            job_run,
            profile,
            hosts,
            locale=resolved_locale,
            waived_check_ids=waived_ids,
            executive=True,
            timeout=settings.blocking_io_timeout_seconds,
        )
    except TimeoutError as exc:
        raise HTTPException(status_code=504, detail="PDF rendering timed out") from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    csv_content, _filename = await fetch_run_csv(db, run_id)
    evidence_run, evidence_waivers, evidence_profile = await load_run_evidence(db, job_run, hosts)
    pack_bytes = build_run_package_zip(
        run_id=run_id,
        html=html,
        pdf=pdf_bytes,
        csv_text=csv_content,
        locale=resolved_locale,
        include_evidence=True,
        evidence_run=evidence_run,
        evidence_waivers=evidence_waivers,
        evidence_profile=evidence_profile,
    )
    return Response(
        content=pack_bytes,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="report-{run_id}-pack.zip"'},
    )


@router.get("/artifacts/{artifact_id}", response_model=ReportArtifactRead)
async def get_report_artifact(
    artifact_id: int,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_reports),
) -> ReportArtifactRead:
    artifact = await db.get(ReportArtifact, artifact_id)
    if artifact is None:
        raise HTTPException(status_code=404, detail="Artifact not found")
    await assert_job_run_access(db, user, artifact.job_run_id)
    return _artifact_read(artifact)


@router.get("/artifacts/{artifact_id}/download")
async def download_report_artifact(
    artifact_id: int,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_reports),
) -> Response:
    artifact = await db.get(ReportArtifact, artifact_id)
    if artifact is None:
        raise HTTPException(status_code=404, detail="Artifact not found")
    await assert_job_run_access(db, user, artifact.job_run_id)
    if artifact.status != "ready" or not artifact.file_path:
        raise HTTPException(status_code=409, detail="Artifact not ready")
    path = Path(artifact.file_path)
    if not path.is_file():
        raise HTTPException(status_code=410, detail="Artifact file missing")
    return Response(
        content=path.read_bytes(),
        media_type="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="report-{artifact.job_run_id}-pack.zip"'
        },
    )
