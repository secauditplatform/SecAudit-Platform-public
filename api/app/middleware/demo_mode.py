"""Block abusable write/execute APIs on public demo stands."""

from __future__ import annotations

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

# Paths that remain writable in demo mode (auth + read-mostly surfaces).
_DEMO_WRITE_ALLOW_PREFIXES = (
    "/api/v1/auth/",
    "/api/v1/health/",
)

# Mutating methods against these prefixes are rejected in demo mode.
_DEMO_BLOCK_WRITE_PREFIXES = (
    "/api/v1/jobs",
    "/api/v1/job-templates",
    "/api/v1/remediations",
    "/api/v1/audit-flow",
    "/api/v1/inventory",
    "/api/v1/playbooks",
    "/api/v1/credentials",
    "/api/v1/hosts",
    "/api/v1/profiles",
    "/api/v1/categories",
    "/api/v1/users",
    "/api/v1/notifications",
    "/api/v1/network",
    "/api/v1/waivers",
    "/api/v1/scheduled-reports",
    "/api/v1/dead-letters",
    "/api/v1/reports",
    "/api/v1/ws",
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

        if any(path.startswith(prefix) for prefix in _DEMO_BLOCK_WRITE_PREFIXES):
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

        return await call_next(request)
