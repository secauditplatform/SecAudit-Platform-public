from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import AuthUser, _decode_local_refresh_token, create_local_token_pair, refresh_local_tokens
from app.core.config import settings
from app.core.database import get_db
from app.core.passwords import verify_password
from app.models import User
from app.services.audit_log import log_audit_event
from app.services.rate_limit import enforce_rate_limit

router = APIRouter()


async def _authenticate_db_user(db: AsyncSession, username: str, password: str) -> User | None:
    result = await db.execute(select(User).where(User.username == username))
    user = result.scalar_one_or_none()
    if not user or not user.is_active:
        return None
    if not verify_password(password, user.hashed_password):
        return None
    return user


async def _resolve_refresh_user(
    db: AsyncSession,
    token_user: AuthUser,
) -> tuple[AuthUser, str]:
    if token_user.local_source not in (None, "database"):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")

    result = await db.execute(select(User).where(User.username == token_user.username))
    db_user = result.scalar_one_or_none()
    if not db_user or not db_user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")

    role = db_user.role.value
    return (
        AuthUser(
            sub=f"local:{db_user.username}",
            username=db_user.username,
            roles=[role],
            auth_mode="local",
            local_source="database",
        ),
        "database",
    )


class LocalLoginRequest(BaseModel):
    username: str
    password: str


class LocalLoginResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    username: str
    expires_in: int


class RefreshTokenRequest(BaseModel):
    refresh_token: str


class RefreshTokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


@router.post("/local", response_model=LocalLoginResponse)
async def local_login(
    data: LocalLoginRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> LocalLoginResponse:
    if not settings.auth_enabled:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Auth is disabled")
    if not settings.local_auth_enabled:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Local login is disabled")

    if settings.local_auth_rate_limit_enabled:
        await enforce_rate_limit(
            request,
            scope="auth_local",
            max_attempts=settings.local_auth_rate_limit_max_attempts,
            window_seconds=settings.local_auth_rate_limit_window_seconds,
        )

    db_user = await _authenticate_db_user(db, data.username, data.password)

    if not db_user:
        await log_audit_event(
            db,
            request,
            user=AuthUser(sub=f"local:{data.username}", username=data.username, roles=[], auth_mode="local"),
            action="auth.local_login",
            resource_type="auth",
            resource_id=data.username,
            resource_name=data.username,
            outcome="failed",
            durable=True,
        )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    username = db_user.username
    role = db_user.role.value
    tokens = create_local_token_pair(username, [role], local_source="database")
    await log_audit_event(
        db,
        request,
        user=AuthUser(
            sub=f"local:{username}",
            username=username,
            roles=[role],
            auth_mode="local",
            local_source="database",
        ),
        action="auth.local_login",
        resource_type="auth",
        resource_id=username,
        resource_name=username,
        metadata={"roles": [role], "source": "database"},
    )
    return LocalLoginResponse(
        access_token=tokens.access_token,
        refresh_token=tokens.refresh_token,
        username=username,
        expires_in=settings.local_auth_token_ttl_seconds,
    )


@router.post("/refresh", response_model=RefreshTokenResponse)
async def refresh_local_access_token(
    data: RefreshTokenRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> RefreshTokenResponse:
    if not settings.auth_enabled:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Auth is disabled")
    if not settings.local_auth_enabled:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Local login is disabled")

    if settings.local_auth_rate_limit_enabled:
        await enforce_rate_limit(
            request,
            scope="auth_refresh",
            max_attempts=settings.local_auth_rate_limit_max_attempts * 3,
            window_seconds=settings.local_auth_rate_limit_window_seconds,
        )

    token_user = _decode_local_refresh_token(data.refresh_token)
    if not token_user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")
    user, local_source = await _resolve_refresh_user(db, token_user)
    tokens = refresh_local_tokens(
        data.refresh_token,
        user.roles,
        local_source=local_source,
    )

    await log_audit_event(
        db,
        request,
        user=user,
        action="auth.refresh",
        resource_type="auth",
        resource_id=user.username,
        resource_name=user.username,
    )
    return RefreshTokenResponse(
        access_token=tokens.access_token,
        refresh_token=tokens.refresh_token,
        expires_in=settings.local_auth_token_ttl_seconds,
    )
