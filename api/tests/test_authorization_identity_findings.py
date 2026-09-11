"""Regression tests for the authorization and local-identity findings."""

from datetime import UTC, datetime
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException

from app.api.v1.routers import inventory, scheduled_reports, waivers
from app.core.auth import AuthUser
from app.models import (
    ComplianceWaiver,
    InventoryScan,
    Job,
    JobRun,
    JobStatus,
    Playbook,
    ScheduledReport,
    ScheduledReportDelivery,
    ScheduledReportFormat,
    UserRole,
    WaiverStatus,
)
from app.services.playbooks import PlaybookService
from app.services.waivers import list_waivers


def _user(role: UserRole, name: str = "alice") -> AuthUser:
    return AuthUser(
        sub=f"local:{name}",
        username=name,
        roles=[role.value],
        auth_mode="local",
    )


def _result(rows):
    return type(
        "Result",
        (),
        {
            "scalars": lambda self: type(
                "Scalars",
                (),
                {"all": lambda self: rows},
            )(),
            "scalar_one_or_none": lambda self: rows[0] if rows else None,
        },
    )()


def _scan(owner: str) -> InventoryScan:
    scan = InventoryScan(
        id=7,
        target="10.0.0.1",
        status=JobStatus.RUNNING,
        hosts_found=0,
        hosts_created=0,
        owner_sub=owner,
        created_at=datetime.now(UTC),
    )
    scan.results = []
    return scan


@pytest.mark.asyncio
async def test_inventory_list_scopes_engineer_but_not_operator():
    sql: list[str] = []
    db = AsyncMock()

    async def execute(stmt):
        sql.append(str(stmt))
        return _result([])

    db.execute = execute
    await inventory.list_inventory_scans(db=db, user=_user(UserRole.OPERATOR))
    await inventory.list_inventory_scans(db=db, user=_user(UserRole.OPERATOR, "operator"))
    assert "inventory_scans.owner_sub" in sql[0]
    assert "inventory_scans.owner_sub =" not in sql[1]


@pytest.mark.asyncio
async def test_inventory_get_hides_cross_owner_and_allows_operator(monkeypatch):
    scan = _scan("local:bob")
    monkeypatch.setattr(inventory, "get_scan_detail", AsyncMock(return_value=scan))
    with pytest.raises(HTTPException) as exc:
        await inventory.get_inventory_scan(7, db=AsyncMock(), user=_user(UserRole.OPERATOR))
    assert exc.value.status_code == 404
    result = await inventory.get_inventory_scan(
        7, db=AsyncMock(), user=_user(UserRole.OPERATOR, "operator")
    )
    assert result.id == 7


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", ["stop", "delete"])
async def test_inventory_mutations_hide_cross_owner_and_allow_operator(monkeypatch, operation):
    scan = _scan("local:bob")
    db = AsyncMock()
    db.get.return_value = scan
    db.refresh = AsyncMock()
    monkeypatch.setattr(inventory, "request_scan_cancel", lambda *_args: None)
    monkeypatch.setattr(
        inventory,
        "cancel_active_run",
        AsyncMock(return_value=True),
    )
    function = (
        inventory.stop_inventory_scan
        if operation == "stop"
        else inventory.delete_inventory_scan
    )
    with pytest.raises(HTTPException) as exc:
        await function(7, db=db, user=_user(UserRole.OPERATOR))
    assert exc.value.status_code == 404

    scan.status = JobStatus.RUNNING
    await function(7, db=db, user=_user(UserRole.OPERATOR, "operator"))


@pytest.mark.asyncio
async def test_playbook_run_rejects_cross_owner_host_before_creating_job():
    host = type(
        "Host",
        (),
        {
            "id": 9,
            "name": "foreign",
            "is_active": True,
            "owner_sub": "local:bob",
        },
    )()
    db = AsyncMock()
    db.get.return_value = host
    with pytest.raises(HTTPException) as exc:
        await PlaybookService().run_playbook(
            db,
            _user(UserRole.OPERATOR),
            Playbook(id=3, name="PB", content="---", is_active=True),
            [9],
        )
    assert exc.value.status_code == 404
    db.add.assert_not_called()


@pytest.mark.asyncio
async def test_playbook_run_assigns_job_owner_and_allows_operator(monkeypatch):
    host = type(
        "Host",
        (),
        {
            "id": 9,
            "name": "foreign",
            "is_active": True,
            "owner_sub": "local:bob",
        },
    )()
    added: list[object] = []
    db = AsyncMock()
    db.get.return_value = host
    db.add = added.append

    async def flush():
        for item in added:
            if isinstance(item, Job):
                item.id = 11
            elif isinstance(item, JobRun):
                item.id = 12

    db.flush = flush
    db.refresh = AsyncMock()
    monkeypatch.setattr(
        "app.services.playbooks.enqueue_run_dispatch",
        AsyncMock(return_value=type("Outbox", (), {"id": 1})()),
    )

    async def dispatch(_db, *, outbox_id, pending_entity):
        pending_entity.status = JobStatus.RUNNING

    monkeypatch.setattr("app.services.playbooks.commit_and_try_dispatch", dispatch)
    operator = _user(UserRole.OPERATOR, "operator")
    run = await PlaybookService().run_playbook(
        db,
        operator,
        Playbook(id=3, name="PB", content="---", is_active=True),
        [9],
    )
    job = next(item for item in added if isinstance(item, Job))
    assert job.owner_sub == operator.sub
    assert job.enforce_host_owner_scope is False
    assert run.id == 12


@pytest.mark.asyncio
async def test_playbook_run_list_scopes_engineer_but_not_operator():
    sql: list[str] = []
    db = AsyncMock()

    async def execute(stmt):
        sql.append(str(stmt))
        return _result([])

    db.execute = execute
    service = PlaybookService()
    await service.list_playbook_runs(db, _user(UserRole.OPERATOR))
    await service.list_playbook_runs(db, _user(UserRole.OPERATOR, "operator"))
    assert "jobs.owner_sub" in sql[0]
    assert "jobs.owner_sub =" not in sql[1]


@pytest.mark.asyncio
async def test_playbook_run_detail_hides_cross_owner_and_allows_operator():
    job = Job(id=2, name="PB run", playbook_id=3, owner_sub="local:bob")
    job.job_hosts = []
    run = JobRun(
        id=4,
        job_id=2,
        status=JobStatus.COMPLETED,
        created_at=datetime.now(UTC),
    )
    run.job = job
    playbook = Playbook(id=3, name="PB", content="---", is_active=True)
    db = AsyncMock()

    async def get(model, key):
        return {JobRun: run, Job: job, Playbook: playbook}.get(model)

    db.get = get
    db.execute.return_value = _result([run])
    service = PlaybookService()
    with pytest.raises(HTTPException) as exc:
        await service.get_playbook_run(db, _user(UserRole.OPERATOR), 4)
    assert exc.value.status_code == 404
    detail = await service.get_playbook_run(
        db, _user(UserRole.OPERATOR, "operator"), 4
    )
    assert detail["id"] == 4


def _schedule() -> ScheduledReport:
    return ScheduledReport(
        id=5,
        name="weekly",
        job_id=8,
        cron_expression="0 1 * * *",
        is_active=True,
        report_format=ScheduledReportFormat.PDF,
        delivery_type=ScheduledReportDelivery.EMAIL,
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )


@pytest.mark.asyncio
async def test_scheduled_report_list_scopes_by_parent_job_owner():
    sql: list[str] = []
    db = AsyncMock()

    async def execute(stmt):
        sql.append(str(stmt))
        return _result([])

    db.execute = execute
    await scheduled_reports.list_scheduled_reports(
        db=db, user=_user(UserRole.OPERATOR)
    )
    await scheduled_reports.list_scheduled_reports(
        db=db, user=_user(UserRole.OPERATOR, "operator")
    )
    assert "jobs.owner_sub" in sql[0]
    assert "jobs.owner_sub =" not in sql[1]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "operation",
    ["get", "update", "delete", "deliver"],
)
async def test_scheduled_report_operations_enforce_parent_job_scope(
    monkeypatch, operation
):
    schedule = _schedule()
    db = AsyncMock()
    db.get.return_value = schedule
    denied = AsyncMock(side_effect=HTTPException(status_code=404, detail="Job not found"))
    monkeypatch.setattr(scheduled_reports, "assert_job_access", denied)
    request = type("Request", (), {"headers": {}, "client": None})()

    if operation == "get":
        call = scheduled_reports.get_scheduled_report(5, db=db, user=_user(UserRole.OPERATOR))
    elif operation == "update":
        call = scheduled_reports.update_scheduled_report(
            5,
            scheduled_reports.ScheduledReportUpdate(),
            request,
            db=db,
            user=_user(UserRole.OPERATOR),
        )
    elif operation == "delete":
        call = scheduled_reports.delete_scheduled_report(
            5, request, db=db, user=_user(UserRole.OPERATOR)
        )
    else:
        call = scheduled_reports.deliver_scheduled_report_now(
            5, request, db=db, user=_user(UserRole.OPERATOR)
        )
    with pytest.raises(HTTPException) as exc:
        await call
    assert exc.value.status_code == 404


@pytest.mark.asyncio
async def test_scheduled_report_get_allows_operator(monkeypatch):
    db = AsyncMock()
    db.get.return_value = _schedule()
    monkeypatch.setattr(scheduled_reports, "assert_job_access", AsyncMock())
    result = await scheduled_reports.get_scheduled_report(
        5, db=db, user=_user(UserRole.OPERATOR, "operator")
    )
    assert result.id == 5


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", ["create", "update", "delete", "deliver"])
async def test_scheduled_report_mutations_allow_admin(monkeypatch, operation):
    schedule = _schedule()
    db = AsyncMock()
    db.get.return_value = schedule
    db.execute.return_value = _result([])
    db.run_sync.return_value = {"delivered": False, "reason": "no completed run"}
    db.refresh = AsyncMock()
    access = AsyncMock()
    monkeypatch.setattr(scheduled_reports, "assert_job_access", access)
    monkeypatch.setattr(scheduled_reports, "log_audit_event", AsyncMock())
    request = type("Request", (), {"headers": {}, "client": None})()
    admin = _user(UserRole.ADMIN, "admin")

    if operation == "create":
        db.add = lambda item: None

        async def refresh(created):
            created.id = 5
            created.created_at = datetime.now(UTC)
            created.updated_at = datetime.now(UTC)

        db.refresh = refresh
        await scheduled_reports.create_scheduled_report(
            scheduled_reports.ScheduledReportCreate(
                name="daily",
                job_id=8,
                cron_expression="0 2 * * *",
                delivery_type=ScheduledReportDelivery.EMAIL,
            ),
            request,
            db=db,
            user=admin,
        )
    elif operation == "update":
        await scheduled_reports.update_scheduled_report(
            5,
            scheduled_reports.ScheduledReportUpdate(is_active=False),
            request,
            db=db,
            user=admin,
        )
    elif operation == "delete":
        await scheduled_reports.delete_scheduled_report(
            5, request, db=db, user=admin
        )
    else:
        await scheduled_reports.deliver_scheduled_report_now(
            5, request, db=db, user=admin
        )
    access.assert_awaited()


def _waiver(owner: str) -> ComplianceWaiver:
    return ComplianceWaiver(
        id=6,
        profile_id=1,
        rule_tech_name="R1",
        reason="accepted risk",
        status=WaiverStatus.PENDING,
        requested_by="bob",
        is_active=True,
        owner_sub=owner,
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )


@pytest.mark.asyncio
async def test_waiver_list_scopes_engineer_but_not_operator():
    sql: list[str] = []
    db = AsyncMock()

    async def execute(stmt):
        sql.append(str(stmt))
        return _result([])

    db.execute = execute
    await list_waivers(db, _user(UserRole.OPERATOR))
    await list_waivers(db, _user(UserRole.OPERATOR, "operator"))
    assert "compliance_waivers.owner_sub" in sql[0]
    assert "compliance_waivers.owner_sub =" not in sql[1]


@pytest.mark.asyncio
async def test_waiver_get_hides_cross_owner_and_allows_operator():
    db = AsyncMock()
    db.get.return_value = _waiver("local:bob")
    with pytest.raises(HTTPException) as exc:
        await waivers.get_compliance_waiver(
            6, db=db, user=_user(UserRole.OPERATOR)
        )
    assert exc.value.status_code == 404
    result = await waivers.get_compliance_waiver(
        6, db=db, user=_user(UserRole.OPERATOR, "operator")
    )
    assert result.id == 6


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", ["update", "delete"])
async def test_waiver_engineer_mutations_hide_cross_owner(operation):
    db = AsyncMock()
    db.get.return_value = _waiver("local:bob")
    request = type("Request", (), {"headers": {}, "client": None})()
    if operation == "update":
        call = waivers.update_compliance_waiver(
            6,
            waivers.ComplianceWaiverUpdate(reason="new reason"),
            request,
            db=db,
            user=_user(UserRole.OPERATOR),
        )
    else:
        call = waivers.delete_compliance_waiver(
            6, request, db=db, user=_user(UserRole.OPERATOR)
        )
    with pytest.raises(HTTPException) as exc:
        await call
    assert exc.value.status_code == 404


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", ["update", "delete"])
async def test_waiver_mutations_allow_operator(monkeypatch, operation):
    db = AsyncMock()
    db.get.return_value = _waiver("local:bob")
    db.refresh = AsyncMock()
    monkeypatch.setattr(waivers, "log_audit_event", AsyncMock())
    request = type("Request", (), {"headers": {}, "client": None})()
    operator = _user(UserRole.OPERATOR, "operator")
    if operation == "update":
        result = await waivers.update_compliance_waiver(
            6,
            waivers.ComplianceWaiverUpdate(reason="operator update"),
            request,
            db=db,
            user=operator,
        )
        assert result.reason == "operator update"
    else:
        await waivers.delete_compliance_waiver(
            6, request, db=db, user=operator
        )
        db.delete.assert_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", ["approve", "reject", "revoke"])
async def test_waiver_workflow_mutations_allow_operator_cross_owner(
    monkeypatch, operation
):
    item = _waiver("local:bob")
    if operation == "revoke":
        item.status = WaiverStatus.APPROVED
    db = AsyncMock()
    db.get.return_value = item
    db.refresh = AsyncMock()
    monkeypatch.setattr(waivers, "log_audit_event", AsyncMock())
    request = type("Request", (), {"headers": {}, "client": None})()
    operator = _user(UserRole.OPERATOR, "operator")
    if operation == "approve":
        result = await waivers.approve_compliance_waiver(
            6, request, db=db, user=operator
        )
    elif operation == "reject":
        result = await waivers.reject_compliance_waiver(
            6,
            waivers.ComplianceWaiverReject(reason="not accepted"),
            request,
            db=db,
            user=operator,
        )
    else:
        result = await waivers.revoke_compliance_waiver(
            6, request, db=db, user=operator
        )
    assert result.status != WaiverStatus.PENDING
