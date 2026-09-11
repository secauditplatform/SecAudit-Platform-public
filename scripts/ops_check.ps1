# SecAudit quick ops check (Compose).
# Usage (from repo root):
#   .\scripts\ops_check.ps1
#   .\scripts\ops_check.ps1 -ApiBase http://localhost:8000 -Token $env:METRICS_BEARER_TOKEN

param(
    [string]$ApiBase = "http://localhost:8000",
    [string]$Token = $env:METRICS_BEARER_TOKEN
)

$ErrorActionPreference = "Continue"
$api = $ApiBase.TrimEnd("/")

function Invoke-Health([string]$Path) {
    $uri = "$api/api/v1$Path"
    try {
        $resp = Invoke-WebRequest -Uri $uri -Method GET -UseBasicParsing -TimeoutSec 10
        Write-Host ("{0} -> {1}" -f $Path, $resp.StatusCode)
        Write-Host $resp.Content
    } catch {
        $status = $null
        if ($_.Exception.Response) {
            $status = [int]$_.Exception.Response.StatusCode
        }
        Write-Host ("{0} -> FAIL {1}: {2}" -f $Path, $status, $_.Exception.Message)
        if ($_.ErrorDetails.Message) { Write-Host $_.ErrorDetails.Message }
    }
}

Write-Host "=== docker compose ps ==="
docker compose ps
Write-Host ""

Write-Host "=== health ==="
Invoke-Health "/health/live"

$readyHeaders = @{}
if ($env:READINESS_BEARER_TOKEN) {
    $readyHeaders["Authorization"] = "Bearer $($env:READINESS_BEARER_TOKEN)"
}
try {
    $ready = Invoke-WebRequest -Uri "$api/api/v1/health/ready" -Headers $readyHeaders -Method GET -UseBasicParsing -TimeoutSec 15
    Write-Host "/health/ready -> $($ready.StatusCode)"
    Write-Host $ready.Content
} catch {
    $status = $null
    if ($_.Exception.Response) { $status = [int]$_.Exception.Response.StatusCode }
    Write-Host "/health/ready -> FAIL $status : $($_.Exception.Message)"
    if ($_.ErrorDetails.Message) { Write-Host $_.ErrorDetails.Message }
}

Write-Host ""
Write-Host "=== redis heartbeat ==="
docker compose exec -T redis-master redis-cli GET secaudit:worker:heartbeat:last_seen
docker compose exec -T redis-master redis-cli GET secaudit:worker:heartbeat:alert_state

Write-Host ""
Write-Host "=== celery ping (worker) ==="
docker compose exec -T worker celery -A app.celery_app inspect ping

if ($Token) {
    Write-Host ""
    Write-Host "=== metrics (heartbeat lines) ==="
    try {
        $m = Invoke-WebRequest -Uri "$api/api/v1/metrics" `
            -Headers @{ Authorization = "Bearer $Token" } `
            -Method GET -UseBasicParsing -TimeoutSec 15
        ($m.Content -split "`n") |
            Where-Object { $_ -match "secaudit_worker_heartbeat" } |
            ForEach-Object { Write-Host $_ }
    } catch {
        Write-Host "metrics -> FAIL: $($_.Exception.Message)"
    }
}

Write-Host ""
Write-Host "Done. Full guide: docs/ops-runbook.md"
