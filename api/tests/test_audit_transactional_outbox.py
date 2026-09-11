import json

import pytest

from app.core.auth import AuthUser
from app.models import AuditLog, TaskOutbox
from app.services.audit_log import log_audit_event
from secaudit_core.enums import OutboxStatus


class _FakeAsyncSession:
    def __init__(self):
        self.rows = []

    def add(self, row):
        self.rows.append(row)

    async def flush(self):
        for index, row in enumerate(self.rows, start=1):
            if row.id is None:
                row.id = index


@pytest.mark.asyncio
async def test_audit_and_siem_intent_share_request_transaction():
    db = _FakeAsyncSession()
    await log_audit_event(
        db,  # type: ignore[arg-type]
        None,
        AuthUser(sub="alice", username="alice", roles=["admin"]),
        action="auth.test",
        resource_type="auth",
        outcome="failed",
        metadata={"Authorization": "Bearer plaintext"},
    )

    event = next(row for row in db.rows if isinstance(row, AuditLog))
    outbox = next(row for row in db.rows if isinstance(row, TaskOutbox))
    payload = json.loads(outbox.args_json)[0]

    assert event.metadata_json["Authorization"] == "[REDACTED]"
    assert outbox.status == OutboxStatus.PENDING
    assert outbox.callback_ref_id == event.id
    assert outbox.celery_task_id == f"secaudit-outbox-{outbox.id}"
    assert payload["audit"]["id"] == event.id
