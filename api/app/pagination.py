from fastapi import Query
from sqlalchemy import Select, func, select
from sqlalchemy.ext.asyncio import AsyncSession

DEFAULT_PAGE_LIMIT = 50
MAX_PAGE_LIMIT = 200


def pagination_params(
    offset: int = Query(0, ge=0),
    limit: int = Query(DEFAULT_PAGE_LIMIT, ge=1, le=MAX_PAGE_LIMIT),
) -> tuple[int, int]:
    return offset, limit


async def paginate_scalars(
    db: AsyncSession,
    stmt: Select,
    *,
    offset: int,
    limit: int,
) -> tuple[list, int]:
    count_stmt = select(func.count()).select_from(stmt.order_by(None).subquery())
    total = (await db.execute(count_stmt)).scalar_one()
    result = await db.execute(stmt.offset(offset).limit(limit))
    return list(result.scalars().all()), total
