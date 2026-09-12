"""Block abusable write/execute APIs on public demo stands."""

from __future__ import annotations

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

# Paths that remain writable in demo mode (auth + health only).
# Deny-by-default: any other mutating method is blocked.
_DEMO_WRITE_ALLOW_PREFIXES = (
    "/api/v1/auth/",
    "/api/v1/health/",
)


class DemoModeGuardMiddleware(BaseHTTPMiddleware):
    """Refuse execute / mutate operations when DEMO_MODE is enabled."""

    def __init__(self, app, *, enabled: bool):
        super().__init__(app)
        self.enabled = enabled

    async def dispatch(self, request: Request, call_next) -> Response:
        if not self.enabled:
            return await call_next(request)

        method = request.method.upper()
        if method in ("GET", "HEAD", "OPTIONS"):
            return await call_next(request)

        path = request.url.path
        if any(path.startswith(prefix) for prefix in _DEMO_WRITE_ALLOW_PREFIXES):
            return await call_next(request)

        return JSONResponse(
            status_code=403,
            content={
                "detail": (
                    "Demo stand: this action is disabled. "
                    "Compliance jobs, remediation, scanning, credentials, "
                    "and other execute/mutate APIs are not available."
                )
            },
        )
