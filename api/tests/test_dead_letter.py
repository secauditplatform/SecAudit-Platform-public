"""Dead-letter queue persistence, replay, and admin API."""

import json
from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from secaudit_core.dead_letter import (
    discard_dead_letter,
    list_dead_letters,
    record_dead_letter,
    replay_dead_letter,
)
from secaudit_core.enums import DeadLetterStatus
from secaudit_core.models import TaskDeadLetter


def _pending_row(**kwargs) -> TaskDeadLetter:
    defaults = {
        "id": 1,
        "celery_task_id": "abc-123",
        "task_name": "app.tasks.run_compliance_job",
        "queue": "compliance",
        "args_json": "[42]",
        "kwargs_json": '{"connection_mode": "auto"}',
        "exception_type": "RuntimeError",
        "exception_message": "boom",
        "retry_count": 3,
        "status": DeadLetterStatus.PENDING,
        "created_at": datetime.now(UTC),
    }
    defaults.update(kwargs)
    return TaskDeadLetter(**defaults)


def test_record_and_list_dead_letters():
    session = MagicMock()
    added: list[TaskDeadLetter] = []

    def _add(row):
        row.id = 7
        added.append(row)

    session.add.side_effect = _add
    session.refresh.side_effect = lambda row: None

    row = record_dead_letter(
        session,
        celery_task_id="task-1",
        task_name="app.tasks.run_compliance_job",
        queue="compliance",
        args=[99],
        kwargs={"connection_mode": "ssh"},
        exc=RuntimeError("host unreachable"),
        traceback_text="Traceback...",
        retry_count=3,
    )

    assert row.id == 7
    assert row.status == DeadLetterStatus.PENDING
    assert json.loads(row.args_json) == [99]
    session.commit.assert_called_once()

    session.reset_mock()
    session.scalars.return_value.all.return_value = added
    session.scalar.return_value = 1
    rows, total = list_dead_letters(session, status=DeadLetterStatus.PENDING, limit=10, offset=0)
    assert total == 1
    assert rows[0].task_name == "app.tasks.run_compliance_job"


@patch("secaudit_core.dead_letter.send_task", return_value="replay-task-id")
def test_replay_dead_letter(mock_send_task):
    session = MagicMock()
    row = _pending_row()
    session.get.return_value = row

    updated = replay_dead_letter(session, 1, broker_url="redis://localhost:6379/0")

    mock_send_task.assert_called_once()
    assert updated.status == DeadLetterStatus.REPLAYED
    assert updated.replay_task_id == "replay-task-id"
    assert updated.replayed_at is not None
    session.commit.assert_called_once()


def test_discard_dead_letter():
    session = MagicMock()
    row = _pending_row()
    session.get.return_value = row

    updated = discard_dead_letter(session, 1)

    assert updated.status == DeadLetterStatus.DISCARDED
    assert updated.discarded_at is not None


def test_replay_rejects_non_pending():
    session = MagicMock()
    session.get.return_value = _pending_row(status=DeadLetterStatus.DISCARDED)
    with pytest.raises(ValueError, match="expected pending"):
        replay_dead_letter(session, 1, broker_url="redis://localhost:6379/0")


def test_dead_letters_api_requires_admin(client: TestClient, operator_headers: dict):
    response = client.get("/api/v1/dead-letters", headers=operator_headers)
    assert response.status_code == 403


@patch("app.api.v1.routers.dead_letters.list_dead_letters_async")
def test_dead_letters_api_list(mock_list, client: TestClient, admin_headers: dict):
    row = _pending_row()
    mock_list.return_value = ([row], 1)

    response = client.get("/api/v1/dead-letters", headers=admin_headers)

    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 1
    assert body["items"][0]["task_name"] == "app.tasks.run_compliance_job"
    assert body["items"][0]["status"] == "pending"


@patch("app.api.v1.routers.dead_letters.replay_dead_letter_async")
def test_dead_letters_api_replay(mock_replay, client: TestClient, admin_headers: dict):
    mock_replay.return_value = _pending_row(
        status=DeadLetterStatus.REPLAYED,
        replay_task_id="new-id",
    )

    response = client.post("/api/v1/dead-letters/1/replay", headers=admin_headers)

    assert response.status_code == 200
    assert response.json()["status"] == "replayed"
    assert response.json()["replay_task_id"] == "new-id"


@patch("app.api.v1.routers.dead_letters.discard_dead_letter_async")
def test_dead_letters_api_discard(mock_discard, client: TestClient, admin_headers: dict):
    mock_discard.return_value = _pending_row(status=DeadLetterStatus.DISCARDED)

    response = client.post("/api/v1/dead-letters/1/discard", headers=admin_headers)

    assert response.status_code == 200
    assert response.json()["status"] == "discarded"
