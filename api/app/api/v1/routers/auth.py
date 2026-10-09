from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import (
    AuthUser,
    _decode_local_refresh_token,
    create_local_token_pair,
    create_mfa_challenge_token,
    decode_mfa_challenge_token,
    extract_local_token_jti,
    get_current_user,
    refresh_local_tokens,
)
from app.core.config import settings
from app.core.database import get_db
from app.core.demo_operators import is_demo_operator_username
from app.core.passwords import verify_password
from app.models import User
from app.services import mfa as mfa_service
from app.services.audit_log import log_audit_event
from app.services.auth_sessions import (
    acquire_auth_session,
    auth_idle_enabled,
    is_auth_token_revoked,
    release_auth_session,
    revoke_auth_token,
    touch_auth_session,
)
from app.services.demo_sessions import acquire_demo_session, release_demo_session, touch_demo_session
from app.services.rate_limit import enforce_rate_limit
from secaudit_core.enums import UserRole

router = APIRouter()
_bearer = HTTPBearer(auto_error=False)


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
    """Either a full token pair, or an MFA challenge when the user enrolled TOTP."""

    access_token: str | None = None
    refresh_token: str | None = None
    token_type: str = "bearer"
    username: str
    expires_in: int | None = None
    mfa_required: bool = False
    mfa_token: str | None = None


class RefreshTokenRequest(BaseModel):
    refresh_token: str


class RefreshTokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class MfaVerifyRequest(BaseModel):
    mfa_token: str
    code: str


class MfaStatusResponse(BaseModel):
    enabled: bool
    recovery_codes_remaining: int = 0


class MfaSetupResponse(BaseModel):
    secret: str
    otpauth_uri: str


class MfaConfirmRequest(BaseModel):
    code: str


class MfaConfirmResponse(BaseModel):
    enabled: bool = True
    recovery_codes: list[str]


class MfaDisableRequest(BaseModel):
    password: str
    code: str


async def _issue_local_login(
    db: AsyncSession,
    request: Request,
    db_user: User,
    *,
    action: str,
    metadata_extra: dict | None = None,
) -> LocalLoginResponse:
    username = db_user.username
    role = db_user.role.value
    session_id = await acquire_auth_session() if auth_idle_enabled() else None
    tokens = create_local_token_pair(username, [role], local_source="database", jti=session_id)
    metadata = {"roles": [role], "source": "database", "session_id": session_id}
    if metadata_extra:
        metadata.update(metadata_extra)
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
        action=action,
        resource_type="auth",
        resource_id=username,
        resource_name=username,
        metadata=metadata,
    )
    return LocalLoginResponse(
        access_token=tokens.access_token,
        refresh_token=tokens.refresh_token,
        username=username,
        expires_in=settings.local_auth_token_ttl_seconds,
    )


async def _require_mfa_capable_user(db: AsyncSession, user: AuthUser) -> User:
    """MFA self-service only applies to database-backed local accounts."""
    if user.auth_mode != "local" or user.local_source not in (None, "database"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="MFA is only available for local accounts",
        )
    result = await db.execute(select(User).where(User.username == user.username))
    db_user = result.scalar_one_or_none()
    if not db_user or not db_user.is_active:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Local user not found")
    return db_user


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
    if settings.demo_mode and not is_demo_operator_username(data.username):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Password login is disabled on the demo stand. Use Sign in.",
        )

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

    if db_user.mfa_enabled:
        username = db_user.username
        await log_audit_event(
            db,
            request,
            user=AuthUser(
                sub=f"local:{username}",
                username=username,
                roles=[db_user.role.value],
                auth_mode="local",
                local_source="database",
            ),
            action="auth.mfa_challenge",
            resource_type="auth",
            resource_id=username,
            resource_name=username,
        )
        return LocalLoginResponse(
            username=username,
            mfa_required=True,
            mfa_token=create_mfa_challenge_token(username),
        )

    return await _issue_local_login(db, request, db_user, action="auth.local_login")


@router.post("/mfa/verify", response_model=LocalLoginResponse)
async def verify_mfa(
    data: MfaVerifyRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> LocalLoginResponse:
    """Second login step: exchange an MFA challenge token for a real token pair."""
    if not settings.auth_enabled:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Auth is disabled")
    if not settings.local_auth_enabled:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Local login is disabled")

    if settings.local_auth_rate_limit_enabled:
        await enforce_rate_limit(
            request,
            scope="auth_mfa",
            max_attempts=settings.local_auth_rate_limit_max_attempts,
            window_seconds=settings.local_auth_rate_limit_window_seconds,
        )

    username = decode_mfa_challenge_token(data.mfa_token)
    if not username:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="MFA challenge expired. Sign in again.",
        )

    result = await db.execute(select(User).where(User.username == username))
    db_user = result.scalar_one_or_none()
    if not db_user or not db_user.is_active or not db_user.mfa_enabled:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    if not mfa_service.verify_mfa_code(db_user, data.code, db):
        await log_audit_event(
            db,
            request,
            user=AuthUser(
                sub=f"local:{username}",
                username=username,
                roles=[],
                auth_mode="local",
                local_source="database",
            ),
            action="auth.mfa_verify",
            resource_type="auth",
            resource_id=username,
            resource_name=username,
            outcome="failed",
            durable=True,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication code",
        )

    return await _issue_local_login(db, request, db_user, action="auth.mfa_verify")


@router.get("/mfa/status", response_model=MfaStatusResponse)
async def mfa_status(
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(get_current_user),
) -> MfaStatusResponse:
    db_user = await _require_mfa_capable_user(db, user)
    return MfaStatusResponse(
        enabled=bool(db_user.mfa_enabled),
        recovery_codes_remaining=len(db_user.mfa_recovery_codes_json or []),
    )


@router.post("/mfa/setup", response_model=MfaSetupResponse)
async def start_mfa_setup(
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(get_current_user),
) -> MfaSetupResponse:
    """Hand out a fresh secret; nothing is written to the DB until /mfa/confirm."""
    db_user = await _require_mfa_capable_user(db, user)
    if db_user.mfa_enabled:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="MFA is already enabled. Disable it first to re-enroll.",
        )
    secret = mfa_service.generate_totp_secret()
    await mfa_service.store_pending_secret(db_user.username, secret)
    return MfaSetupResponse(
        secret=secret,
        otpauth_uri=mfa_service.build_otpauth_uri(db_user.username, secret),
    )


@router.post("/mfa/confirm", response_model=MfaConfirmResponse)
async def confirm_mfa_setup(
    data: MfaConfirmRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(get_current_user),
) -> MfaConfirmResponse:
    db_user = await _require_mfa_capable_user(db, user)
    if db_user.mfa_enabled:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="MFA is already enabled. Disable it first to re-enroll.",
        )

    secret = await mfa_service.load_pending_secret(db_user.username)
    if not secret:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="MFA enrollment expired. Start setup again.",
        )
    if not mfa_service.verify_totp(secret, data.code):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid authentication code",
        )

    codes = mfa_service.generate_recovery_codes(settings.local_auth_mfa_recovery_code_count)
    db_user.mfa_enabled = True
    db_user.totp_secret_encrypted = mfa_service.encrypt_totp_secret(secret)
    db_user.mfa_recovery_codes_json = mfa_service.hash_recovery_codes(codes)
    db.add(db_user)
    await db.flush()
    await mfa_service.discard_pending_secret(db_user.username)
    await log_audit_event(
        db,
        request,
        user,
        action="auth.mfa_enable",
        resource_type="user",
        resource_id=str(db_user.id),
        resource_name=db_user.username,
    )
    return MfaConfirmResponse(recovery_codes=codes)


@router.post("/mfa/disable", status_code=status.HTTP_204_NO_CONTENT)
async def disable_mfa(
    data: MfaDisableRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(get_current_user),
) -> None:
    db_user = await _require_mfa_capable_user(db, user)
    if not db_user.mfa_enabled:
        return None

    if settings.local_auth_rate_limit_enabled:
        await enforce_rate_limit(
            request,
            scope="auth_mfa",
            max_attempts=settings.local_auth_rate_limit_max_attempts,
            window_seconds=settings.local_auth_rate_limit_window_seconds,
        )

    if not verify_password(data.password, db_user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    if not mfa_service.verify_mfa_code(db_user, data.code, db):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication code",
        )

    mfa_service.clear_mfa(db_user)
    db.add(db_user)
    await db.flush()
    await mfa_service.discard_pending_secret(db_user.username)
    await log_audit_event(
        db,
        request,
        user,
        action="auth.mfa_disable",
        resource_type="user",
        resource_id=str(db_user.id),
        resource_name=db_user.username,
    )
    return None


@router.post("/demo", response_model=LocalLoginResponse)
async def demo_login(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> LocalLoginResponse:
    """One-click demo stand sign-in as the bootstrap admin (session-capped)."""
    if not settings.auth_enabled:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Auth is disabled")
    if not settings.demo_mode:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Demo login is disabled")
    if not settings.local_auth_enabled:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Local login is disabled")

    if settings.local_auth_rate_limit_enabled:
        await enforce_rate_limit(
            request,
            scope="auth_demo",
            max_attempts=settings.local_auth_rate_limit_max_attempts * 2,
            window_seconds=settings.local_auth_rate_limit_window_seconds,
        )

    preferred = (settings.bootstrap_admin_username or "admin").strip()
    result = await db.execute(select(User).where(User.username == preferred))
    db_user = result.scalar_one_or_none()
    if not db_user or not db_user.is_active:
        result = await db.execute(
            select(User).where(User.role == UserRole.ADMIN, User.is_active.is_(True)).limit(1)
        )
        db_user = result.scalar_one_or_none()
    if not db_user:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Demo admin user is not available",
        )

    session_id = await acquire_demo_session(ttl_seconds=settings.demo_session_idle_seconds)
    tokens = create_local_token_pair(
        db_user.username,
        [UserRole.ADMIN.value],
        local_source="database",
        jti=session_id,
    )
    await log_audit_event(
        db,
        request,
        user=AuthUser(
            sub=f"local:{db_user.username}",
            username=db_user.username,
            roles=[UserRole.ADMIN.value],
            auth_mode="local",
            local_source="database",
        ),
        action="auth.demo_login",
        resource_type="auth",
        resource_id=db_user.username,
        resource_name=db_user.username,
        metadata={"roles": [UserRole.ADMIN.value], "source": "demo", "session_id": session_id},
    )
    return LocalLoginResponse(
        access_token=tokens.access_token,
        refresh_token=tokens.refresh_token,
        username=db_user.username,
        expires_in=settings.local_auth_token_ttl_seconds,
    )


@router.post("/demo/logout", status_code=status.HTTP_204_NO_CONTENT)
async def demo_logout(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> None:
    if not settings.demo_mode:
        return None
    token = credentials.credentials if credentials else None
    if not token:
        auth = request.headers.get("authorization") or ""
        if auth.lower().startswith("bearer "):
            token = auth.split(" ", 1)[1].strip()
    await release_demo_session(extract_local_token_jti(token or ""))
    return None


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def local_logout(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> None:
    """Revoke the local access token and release the idle session."""
    token = credentials.credentials if credentials else None
    if not token:
        auth = request.headers.get("authorization") or ""
        if auth.lower().startswith("bearer "):
            token = auth.split(" ", 1)[1].strip()
    jti = extract_local_token_jti(token or "")
    if settings.demo_mode:
        await release_demo_session(jti)
    else:
        await release_auth_session(jti)
        if jti and token:
            # Blacklist until access token expiry (best-effort from configured TTL).
            await revoke_auth_token(jti, ttl_seconds=settings.local_auth_token_ttl_seconds)
    return None


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
    jti = extract_local_token_jti(data.refresh_token)
    if settings.demo_mode and jti:
        await touch_demo_session(jti, ttl_seconds=settings.demo_session_idle_seconds)
    elif jti and auth_idle_enabled():
        await touch_auth_session(jti)
    tokens = refresh_local_tokens(
        data.refresh_token,
        user.roles if not settings.demo_mode else [UserRole.ADMIN.value],
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
