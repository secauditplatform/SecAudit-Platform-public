import asyncio
import json
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import httpx
from fastapi import Depends, HTTPException, WebSocket, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt

from app.core.config import settings
from secaudit_core.enums import UserRole
from secaudit_core.rbac import normalize_roles

bearer_scheme = HTTPBearer(auto_error=False)

_jwks_cache: dict | None = None
_jwks_cache_fetched_at: float = 0.0
_jwks_cache_lock = asyncio.Lock()
_JWKS_CACHE_TTL_SECONDS = 300
WS_AUTH_TIMEOUT_SECONDS = 10.0
LOCAL_TOKEN_TYPE = "local"
LOCAL_REFRESH_TOKEN_TYPE = "local_refresh"


@dataclass
class LocalTokenPair:
    access_token: str
    refresh_token: str


@dataclass
class AuthUser:
    sub: str
    username: str
    roles: list[str]
    auth_mode: str = "unknown"
    local_source: str | None = None

    def has_role(self, *roles: UserRole | str) -> bool:
        allowed = {r.value if isinstance(r, UserRole) else r for r in roles}
        return bool(set(self.roles) & allowed) or UserRole.ADMIN.value in self.roles


def create_local_token(
    username: str,
    roles: list[str],
    *,
    local_source: str | None = None,
) -> str:
    now = datetime.now(UTC)
    ttl = settings.local_auth_token_ttl_seconds
    return jwt.encode(
        {
            "sub": f"local:{username}",
            "preferred_username": username,
            "realm_access": {"roles": roles},
            "typ": LOCAL_TOKEN_TYPE,
            "local_source": local_source,
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(seconds=ttl)).timestamp()),
        },
        settings.secret_key,
        algorithm="HS256",
    )


def create_local_refresh_token(
    username: str,
    roles: list[str],
    *,
    local_source: str | None = None,
) -> str:
    now = datetime.now(UTC)
    ttl = settings.local_auth_refresh_token_ttl_seconds
    return jwt.encode(
        {
            "sub": f"local:{username}",
            "preferred_username": username,
            "realm_access": {"roles": roles},
            "typ": LOCAL_REFRESH_TOKEN_TYPE,
            "local_source": local_source,
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(seconds=ttl)).timestamp()),
        },
        settings.secret_key,
        algorithm="HS256",
    )


def create_local_token_pair(
    username: str,
    roles: list[str],
    *,
    local_source: str | None = None,
) -> LocalTokenPair:
    return LocalTokenPair(
        access_token=create_local_token(username, roles, local_source=local_source),
        refresh_token=create_local_refresh_token(username, roles, local_source=local_source),
    )


def _decode_local_refresh_token(token: str) -> AuthUser | None:
    if not settings.local_auth_enabled:
        return None
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=["HS256"])
    except JWTError:
        return None

    if payload.get("typ") != LOCAL_REFRESH_TOKEN_TYPE:
        return None

    realm_access = payload.get("realm_access", {})
    roles = normalize_roles(realm_access.get("roles", []))
    username = payload.get("preferred_username") or payload.get("sub", "unknown")
    return AuthUser(
        sub=payload.get("sub", ""),
        username=username,
        roles=roles,
        auth_mode="local",
        local_source=payload.get("local_source"),
    )


def refresh_local_tokens(
    refresh_token: str,
    current_roles: list[str],
    *,
    local_source: str | None = None,
) -> LocalTokenPair:
    user = _decode_local_refresh_token(refresh_token)
    if not user or not user.username:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")
    return create_local_token_pair(
        user.username,
        current_roles,
        local_source=local_source or user.local_source,
    )


def _decode_local_token(token: str) -> AuthUser | None:
    if not settings.local_auth_enabled:
        return None
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=["HS256"])
    except JWTError:
        return None

    if payload.get("typ") != LOCAL_TOKEN_TYPE:
        return None

    realm_access = payload.get("realm_access", {})
    roles = normalize_roles(realm_access.get("roles", []))
    username = payload.get("preferred_username") or payload.get("sub", "unknown")
    return AuthUser(
        sub=payload.get("sub", ""),
        username=username,
        roles=roles,
        auth_mode="local",
        local_source=payload.get("local_source"),
    )


async def _fetch_jwks() -> dict:
    timeout = httpx.Timeout(10.0)
    async with httpx.AsyncClient(timeout=timeout) as client:
        response = await client.get(settings.keycloak_jwks_url)
        response.raise_for_status()
        return response.json()


async def _get_jwks(*, force_refresh: bool = False) -> dict:
    global _jwks_cache, _jwks_cache_fetched_at
    now = time.monotonic()
    stale = _jwks_cache is None or (now - _jwks_cache_fetched_at) > _JWKS_CACHE_TTL_SECONDS
    if force_refresh or stale:
        async with _jwks_cache_lock:
            now = time.monotonic()
            stale = (
                _jwks_cache is None
                or (now - _jwks_cache_fetched_at) > _JWKS_CACHE_TTL_SECONDS
            )
            if force_refresh or stale:
                _jwks_cache = await _fetch_jwks()
                _jwks_cache_fetched_at = time.monotonic()
    assert _jwks_cache is not None
    return _jwks_cache


def _decode_keycloak_token_with_jwks(token: str, jwks: dict) -> AuthUser:
    header = jwt.get_unverified_header(token)
    token_alg = header.get("alg")
    allowed_algs = settings.keycloak_jwt_algorithms_list
    if not token_alg or token_alg not in allowed_algs:
        raise JWTError("Unsupported JWT algorithm")

    key = next((k for k in jwks["keys"] if k["kid"] == header.get("kid")), None)
    if not key:
        raise JWTError("Invalid token key")

    payload = jwt.decode(
        token,
        key,
        algorithms=allowed_algs,
        audience=settings.keycloak_audience,
        issuer=settings.keycloak_issuer_url,
        options={"verify_aud": True, "verify_iss": True},
    )

    realm_access = payload.get("realm_access", {})
    roles = normalize_roles(realm_access.get("roles", []))
    username = (
        payload.get("preferred_username")
        or payload.get("username")
        or payload.get("email")
        or payload.get("sub", "unknown")
    )
    return AuthUser(sub=payload.get("sub", ""), username=username, roles=roles, auth_mode="sso")


async def _decode_keycloak_token(token: str) -> AuthUser:
    try:
        return _decode_keycloak_token_with_jwks(token, await _get_jwks())
    except JWTError:
        try:
            return _decode_keycloak_token_with_jwks(
                token, await _get_jwks(force_refresh=True)
            )
        except JWTError as exc:
            raise HTTPException(status_code=401, detail="Invalid token") from exc


async def _decode_token(token: str) -> AuthUser:
    local_user = _decode_local_token(token)
    if local_user:
        return local_user

    try:
        return await _decode_keycloak_token(token)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=401, detail="Invalid token") from exc


async def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
) -> AuthUser:
    if not settings.auth_enabled:
        return AuthUser(
            sub="anonymous",
            username="anonymous",
            roles=[UserRole.ADMIN.value],
            auth_mode="disabled",
        )

    if not credentials:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    return await _decode_token(credentials.credentials)


def require_roles(*roles: UserRole):
    async def checker(user: AuthUser = Depends(get_current_user)) -> AuthUser:
        if not user.has_role(*roles, UserRole.ADMIN):
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        return user

    return checker


async def resolve_ws_user(token: str | None) -> AuthUser | None:
    if not settings.auth_enabled:
        return AuthUser(
            sub="anonymous",
            username="anonymous",
            roles=[UserRole.ADMIN.value],
            auth_mode="disabled",
        )

    if not token:
        return None

    try:
        return await _decode_token(token)
    except HTTPException:
        return None


async def authenticate_websocket(websocket: WebSocket) -> tuple[AuthUser | None, str | None]:
    """Accept WebSocket and authenticate via first JSON auth frame (not query string)."""
    await websocket.accept()
    if not settings.auth_enabled:
        return (
            AuthUser(
                sub="anonymous",
                username="anonymous",
                roles=[UserRole.ADMIN.value],
                auth_mode="disabled",
            ),
            None,
        )

    try:
        raw = await asyncio.wait_for(
            websocket.receive_text(),
            timeout=WS_AUTH_TIMEOUT_SECONDS,
        )
        data = json.loads(raw)
    except (asyncio.TimeoutError, json.JSONDecodeError, TypeError):
        return None, None

    if data.get("type") != "auth":
        return None, None

    token = data.get("token")
    if not isinstance(token, str) or not token.strip():
        return None, None

    user = await resolve_ws_user(token.strip())
    return user, token.strip()
