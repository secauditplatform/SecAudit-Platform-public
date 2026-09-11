from fastapi import APIRouter, Depends, HTTPException, Query

from app.core.auth import AuthUser, require_roles
from app.core.config import settings
from app.models import DeadLetterStatus, UserRole
from app.pagination import pagination_params
from app.schemas import DeadLetterRead, PaginatedResponse
from app.services.dead_letter import (
    discard_dead_letter_async,
    list_dead_letters_async,
    replay_dead_letter_async,
)

router = APIRouter()


@router.get("", response_model=PaginatedResponse[DeadLetterRead])
async def list_dead_letters(
    _: AuthUser = Depends(require_roles(UserRole.ADMIN)),
    page: tuple[int, int] = Depends(pagination_params),
    status: DeadLetterStatus | None = Query(default=DeadLetterStatus.PENDING),
) -> PaginatedResponse[DeadLetterRead]:
    offset, limit = page
    rows, total = await list_dead_letters_async(
        database_url=settings.database_url_sync,
        status=status,
        limit=limit,
        offset=offset,
    )
    return PaginatedResponse[DeadLetterRead](
        items=[DeadLetterRead.model_validate(row) for row in rows],
        total=total,
        offset=offset,
        limit=limit,
    )


@router.post("/{dead_letter_id}/replay", response_model=DeadLetterRead)
async def replay_dead_letter(
    dead_letter_id: int,
    _: AuthUser = Depends(require_roles(UserRole.ADMIN)),
) -> DeadLetterRead:
    try:
        row = await replay_dead_letter_async(
            dead_letter_id,
            database_url=settings.database_url_sync,
            broker_url=settings.celery_broker_url,
        )
    except LookupError:
        raise HTTPException(status_code=404, detail="Dead letter not found") from None
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return DeadLetterRead.model_validate(row)


@router.post("/{dead_letter_id}/discard", response_model=DeadLetterRead)
async def discard_dead_letter(
    dead_letter_id: int,
    _: AuthUser = Depends(require_roles(UserRole.ADMIN)),
) -> DeadLetterRead:
    try:
        row = await discard_dead_letter_async(
            dead_letter_id,
            database_url=settings.database_url_sync,
        )
    except LookupError:
        raise HTTPException(status_code=404, detail="Dead letter not found") from None
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return DeadLetterRead.model_validate(row)
