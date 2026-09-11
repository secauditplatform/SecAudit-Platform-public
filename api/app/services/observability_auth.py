"""Shared auth helper for metrics / readiness observability endpoints."""

from __future__ import annotations

import hmac

from fastapi import HTTPException, Request, status

from app.core.config import settings


def require_observability_token(
    request: Request,
    *,
    configured_token: str | None,
    endpoint_name: str,
    require_in_production: bool = False,
) -> None:
    """Enforce Bearer / X-Observability-Token when a token is configured.

    In production, metrics require a configured token (fail closed). Readiness
    may stay public for orchestrators when no token is set, but details are redacted.
    """
    token = (configured_token or "").strip() or None
    if token is None:
        if require_in_production and settings.app_env == "production":
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=f"{endpoint_name} disabled: bearer token not configured",
            )
        return

    auth = request.headers.get("authorization") or ""
    provided: str | None = None
    if auth.lower().startswith("bearer "):
        provided = auth[7:].strip()
    if not provided:
        provided = (request.headers.get("x-observability-token") or "").strip() or None

    if not provided or not hmac.compare_digest(provided, token):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"{endpoint_name} requires a valid observability token",
            headers={"WWW-Authenticate": "Bearer"},
        )
