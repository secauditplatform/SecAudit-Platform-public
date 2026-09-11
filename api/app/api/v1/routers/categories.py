from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import AuthUser, require_roles
from app.core.roles import require_operate
from app.core.database import get_db
from app.models import UserRole
from app.schemas import CategoryCreate, CategoryRead
from app.services.profiles import CategoryService

router = APIRouter()
category_service = CategoryService()


@router.get("", response_model=list[CategoryRead])
async def list_categories(
    db: AsyncSession = Depends(get_db),
    _: AuthUser = Depends(require_operate),
) -> list[CategoryRead]:
    categories = await category_service.list_categories(db)
    return [CategoryRead.model_validate(c) for c in categories]


@router.post("", response_model=CategoryRead, status_code=201)
async def create_category(
    data: CategoryCreate,
    db: AsyncSession = Depends(get_db),
    _: AuthUser = Depends(require_roles(UserRole.OPERATOR, UserRole.ADMIN)),
) -> CategoryRead:
    from app.models import Category

    category = Category(**data.model_dump())
    db.add(category)
    await db.flush()
    await db.refresh(category)
    return CategoryRead.model_validate(category)


@router.post("/seed", response_model=list[CategoryRead])
async def seed_categories(
    db: AsyncSession = Depends(get_db),
    _: AuthUser = Depends(require_roles(UserRole.OPERATOR, UserRole.ADMIN)),
) -> list[CategoryRead]:
    await category_service.seed_defaults(db)
    categories = await category_service.list_categories(db)
    return [CategoryRead.model_validate(c) for c in categories]
