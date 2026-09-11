from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import AuthUser, require_roles
from app.core.database import get_db
from app.core.passwords import hash_password
from app.models import Job, User, UserRole
from app.schemas import UserCreate, UserRead, UserUpdate
from app.services.audit_log import log_audit_event

router = APIRouter()


async def _count_admins(db: AsyncSession) -> int:
    result = await db.execute(
        select(func.count())
        .select_from(User)
        .where(User.role == UserRole.ADMIN, User.is_active.is_(True))
    )
    return int(result.scalar_one())


async def _get_user_or_404(db: AsyncSession, user_id: int) -> User:
    user = await db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


@router.get("", response_model=list[UserRead])
async def list_users(
    db: AsyncSession = Depends(get_db),
    _: AuthUser = Depends(require_roles(UserRole.ADMIN)),
) -> list[UserRead]:
    result = await db.execute(select(User).order_by(User.username))
    return [UserRead.model_validate(user) for user in result.scalars().all()]


@router.post("", response_model=UserRead, status_code=201)
async def create_user(
    data: UserCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    actor: AuthUser = Depends(require_roles(UserRole.ADMIN)),
) -> UserRead:
    existing = await db.execute(
        select(User).where((User.username == data.username) | (User.email == data.email))
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="User with this username or email already exists")

    user = User(
        username=data.username,
        email=data.email,
        full_name=data.full_name,
        role=data.role,
        hashed_password=hash_password(data.password),
        is_active=True,
    )
    db.add(user)
    await db.flush()
    await db.refresh(user)
    await log_audit_event(
        db,
        request,
        actor,
        action="user.create",
        resource_type="user",
        resource_id=str(user.id),
        resource_name=user.username,
        metadata={"role": user.role.value},
    )
    return UserRead.model_validate(user)


@router.get("/{user_id}", response_model=UserRead)
async def get_user(
    user_id: int,
    db: AsyncSession = Depends(get_db),
    _: AuthUser = Depends(require_roles(UserRole.ADMIN)),
) -> UserRead:
    user = await _get_user_or_404(db, user_id)
    return UserRead.model_validate(user)


@router.patch("/{user_id}", response_model=UserRead)
async def update_user(
    user_id: int,
    data: UserUpdate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    actor: AuthUser = Depends(require_roles(UserRole.ADMIN)),
) -> UserRead:
    user = await _get_user_or_404(db, user_id)
    updates = data.model_dump(exclude_unset=True)
    password = updates.pop("password", None)

    if "username" in updates and updates["username"] != user.username:
        existing = await db.execute(select(User).where(User.username == updates["username"]))
        if existing.scalar_one_or_none():
            raise HTTPException(status_code=409, detail="Username already taken")
        user.username = updates["username"]

    if "email" in updates and updates["email"] != user.email:
        existing = await db.execute(select(User).where(User.email == updates["email"]))
        if existing.scalar_one_or_none():
            raise HTTPException(status_code=409, detail="Email already taken")
        user.email = updates["email"]

    if "full_name" in updates:
        user.full_name = updates["full_name"]

    new_role = updates.get("role")
    new_active = updates.get("is_active")

    if user.username == actor.username:
        if new_active is False:
            raise HTTPException(status_code=409, detail="Cannot deactivate your own account")
        if new_role is not None and new_role != UserRole.ADMIN:
            raise HTTPException(status_code=409, detail="Cannot change your own admin role")

    if new_role is not None and new_role != user.role:
        if user.role == UserRole.ADMIN and (await _count_admins(db)) <= 1:
            raise HTTPException(status_code=409, detail="Cannot remove the last active admin")
        user.role = new_role

    if new_active is not None:
        if not new_active and user.role == UserRole.ADMIN and (await _count_admins(db)) <= 1:
            raise HTTPException(status_code=409, detail="Cannot deactivate the last active admin")
        user.is_active = new_active

    if password:
        user.hashed_password = hash_password(password)

    await db.flush()
    await db.refresh(user)
    await log_audit_event(
        db,
        request,
        actor,
        action="user.update",
        resource_type="user",
        resource_id=str(user.id),
        resource_name=user.username,
        metadata={"role": user.role.value, "is_active": user.is_active},
    )
    return UserRead.model_validate(user)


@router.delete("/{user_id}", status_code=204)
async def delete_user(
    user_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
    actor: AuthUser = Depends(require_roles(UserRole.ADMIN)),
) -> None:
    user = await _get_user_or_404(db, user_id)
    if user.username == actor.username:
        raise HTTPException(status_code=409, detail="Cannot delete your own account")
    if user.role == UserRole.ADMIN and (await _count_admins(db)) <= 1:
        raise HTTPException(status_code=409, detail="Cannot delete the last active admin")

    job_ref = await db.execute(select(Job.id).where(Job.created_by_id == user.id).limit(1))
    if job_ref.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="User is referenced by jobs")

    username = user.username
    await db.delete(user)
    await log_audit_event(
        db,
        request,
        actor,
        action="user.delete",
        resource_type="user",
        resource_id=str(user_id),
        resource_name=username,
    )
