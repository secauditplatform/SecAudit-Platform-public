from fastapi import APIRouter

from app.api.v1.routers import (
    audit_flow,
    audit_logs,
    auth,
    categories,
    credentials,
    dead_letters,
    health,
    hosts,
    inventory,
    job_templates,
    jobs,
    metrics,
    network_operations,
    notifications,
    playbooks,
    remediations,
    reports,
    scheduled_reports,
    search,
    profiles,
    users,
    waivers,
    ws,
)

api_router = APIRouter()
api_router.include_router(health.router, tags=["health"])
api_router.include_router(metrics.router, tags=["metrics"])
api_router.include_router(auth.router, prefix="/auth", tags=["auth"])
api_router.include_router(audit_logs.router, prefix="/audit-logs", tags=["audit-logs"])
api_router.include_router(search.router, prefix="/search", tags=["search"])
api_router.include_router(categories.router, prefix="/categories", tags=["categories"])
api_router.include_router(profiles.router, prefix="/profiles", tags=["profiles"])
api_router.include_router(credentials.router, prefix="/credentials", tags=["credentials"])
api_router.include_router(users.router, prefix="/users", tags=["users"])
api_router.include_router(notifications.router, prefix="/notifications", tags=["notifications"])
api_router.include_router(hosts.router, prefix="/hosts", tags=["hosts"])
api_router.include_router(inventory.router, prefix="/inventory", tags=["inventory"])
api_router.include_router(audit_flow.router, prefix="/audit-flow", tags=["audit-flow"])
api_router.include_router(jobs.router, prefix="/jobs", tags=["jobs"])
api_router.include_router(network_operations.router, prefix="/network", tags=["network"])
api_router.include_router(job_templates.router, prefix="/job-templates", tags=["job-templates"])
api_router.include_router(remediations.router, prefix="/remediations", tags=["remediations"])
api_router.include_router(playbooks.router, prefix="/playbooks", tags=["playbooks"])
api_router.include_router(reports.router, prefix="/reports", tags=["reports"])
api_router.include_router(waivers.router, prefix="/waivers", tags=["waivers"])
api_router.include_router(dead_letters.router, prefix="/dead-letters", tags=["dead-letters"])
api_router.include_router(
    scheduled_reports.router, prefix="/scheduled-reports", tags=["scheduled-reports"]
)
api_router.include_router(ws.router, prefix="/ws", tags=["websocket"])
