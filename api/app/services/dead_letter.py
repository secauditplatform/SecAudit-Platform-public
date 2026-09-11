"""Async wrappers for Celery dead-letter admin operations."""

from __future__ import annotations

import asyncio

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from secaudit_core.dead_letter import discard_dead_letter, list_dead_letters, replay_dead_letter
from secaudit_core.enums import DeadLetterStatus
from secaudit_core.models import TaskDeadLetter


def _session_factory(database_url: str):
    engine = create_engine(database_url, pool_pre_ping=True)
    return sessionmaker(bind=engine)


async def list_dead_letters_async(
    *,
    database_url: str,
    status: DeadLetterStatus | None = DeadLetterStatus.PENDING,
    limit: int = 100,
    offset: int = 0,
) -> tuple[list[TaskDeadLetter], int]:
    def _run() -> tuple[list[TaskDeadLetter], int]:
        SessionLocal = _session_factory(database_url)
        with SessionLocal() as session:
            return list_dead_letters(session, status=status, limit=limit, offset=offset)

    return await asyncio.to_thread(_run)


async def replay_dead_letter_async(
    dead_letter_id: int,
    *,
    database_url: str,
    broker_url: str,
) -> TaskDeadLetter:
    def _run() -> TaskDeadLetter:
        SessionLocal = _session_factory(database_url)
        with SessionLocal() as session:
            return replay_dead_letter(
                session,
                dead_letter_id,
                broker_url=broker_url,
            )

    return await asyncio.to_thread(_run)


async def discard_dead_letter_async(
    dead_letter_id: int,
    *,
    database_url: str,
) -> TaskDeadLetter:
    def _run() -> TaskDeadLetter:
        SessionLocal = _session_factory(database_url)
        with SessionLocal() as session:
            return discard_dead_letter(session, dead_letter_id)

    return await asyncio.to_thread(_run)
