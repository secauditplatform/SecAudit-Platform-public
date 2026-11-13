"""Block abusable write/execute APIs on public demo stands."""

from __future__ import annotations

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from app.core.auth import _decode_local_token
from app.core.demo_operators import is_demo_operator_username

# Paths that remain writable in demo mode (auth + read-mostly surfaces).
_DEMO_WRITE_ALLOW_PREFIXES = (
    "/api/v1/auth/",
    "/api/v1/health/",
)

# Mutating methods against these prefixes are rejected in demo mode.
# Jobs / job-templates / remediations / playbooks / audit-map stay open so guests
# can run seeded lab targets; execution itself is limited to DEMO_EXEC_ALLOWED_CIDRS.
_DEMO_BLOCK_WRITE_PREFIXES = (
    "/api/v1/audit-flow",
    "/api/v1/inventory",
    "/api/v1/directory",
    "/api/v1/credentials",
    "/api/v1/hosts",
    "/api/v1/profiles",
    "/api/v1/categories",
    "/api/v1/users",
    "/api/v1/api-keys",
    "/api/v1/notifications",
    "/api/v1/network",
    "/api/v1/waivers",
    "/api/v1/scheduled-reports",
    "/api/v1/dead-letters",
    "/api/v1/reports",
    "/api/v1/ws",
    "/api/v1/aag",
    "/api/v1/cve-feed",
)


def _bearer_is_demo_operator(request: Request) -> bool:
    auth = request.headers.get("authorization") or ""
    if not auth.lower().startswith("bearer "):
        return False
    token = auth.split(" ", 1)[1].strip()
    if not token:
        return False
    user = _decode_local_token(token)
    if not user:
        return False
    return is_demo_operator_username(user.username)


class DemoModeGuardMiddleware(BaseHTTPMiddleware):
    """Refuse mutate operations when DEMO_MODE is enabled (except operators)."""

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
            if _bearer_is_demo_operator(request):
                return await call_next(request)
            return JSONResponse(
                status_code=403,
                content={
                    "detail": (
                        "Demo stand: this action is disabled. "
                        "Hosts, credentials, users, scans, and other "
                        "infrastructure mutate APIs are not available. "
                        "Compliance, remediation, and playbook runs are limited "
                        "to local lab networks."
                    )
                },
            )

        return await call_next(request)
