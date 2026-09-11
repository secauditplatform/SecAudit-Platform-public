# SecAudit backup wrapper (Compose lab).
# Usage (from repo root):
#   .\scripts\backup.ps1
#   .\scripts\backup.ps1 -StopWriters
#   .\scripts\backup.ps1 -IncludeProfilesSource

param(
    [string]$BackupRoot = "backups",
    [switch]$StopWriters,
    [switch]$IncludeProfilesSource
)

$ErrorActionPreference = "Stop"

$ts = Get-Date -Format "yyyyMMdd_HHmmss"
$dest = Join-Path $BackupRoot "backup_$ts"
New-Item -ItemType Directory -Force -Path $dest | Out-Null

Write-Host "=== SecAudit backup -> $dest ==="

function Get-ProfilesVolumeName {
    $vol = docker volume ls -q --filter name=profiles_data | Select-Object -First 1
    if (-not $vol) {
        throw "Docker volume matching 'profiles_data' not found. Is Compose up?"
    }
    return $vol
}

$stopped = @()
if ($StopWriters) {
    Write-Host "Stopping api worker beat (brief writers pause)..."
    docker compose stop api worker beat | Out-Null
    $stopped = @("api", "worker", "beat")
}

try {
    Write-Host "PostgreSQL pg_dump (custom format)..."
    docker compose exec postgres pg_dump -U secaudit -d secaudit -Fc -f /tmp/secaudit.dump
    if ($LASTEXITCODE -ne 0) { throw "pg_dump failed with exit code $LASTEXITCODE" }
    docker compose cp postgres:/tmp/secaudit.dump (Join-Path $dest "postgres_secaudit.dump")
    docker compose exec postgres rm -f /tmp/secaudit.dump | Out-Null

    $vol = Get-ProfilesVolumeName
    Write-Host "Archiving volume $vol -> profiles_data.tar.gz ..."
    $destAbs = (Resolve-Path $dest).Path
    docker run --rm `
        -v "${vol}:/data:ro" `
        -v "${destAbs}:/backup" `
        alpine tar czf /backup/profiles_data.tar.gz -C /data .

    if ($IncludeProfilesSource) {
        $profilesTar = Join-Path $dest "profiles_source.tar.gz"
        if (Get-Command tar -ErrorAction SilentlyContinue) {
            Write-Host "Archiving ./profiles -> profiles_source.tar.gz ..."
            tar -czf $profilesTar -C profiles .
        } else {
            Write-Warning "tar not found; skipping profiles source (use WSL tar or -IncludeProfilesSource on Git Bash)"
        }
    }

    Write-Host "Writing manifest..."
    $alembic = ""
    try {
        $alembic = (docker compose exec -T api alembic current 2>$null).Trim()
    } catch {
        $alembic = "unknown (api not running)"
    }

    @"
backup_timestamp=$ts
postgres_db=secaudit
profiles_volume=$vol
alembic_current=$alembic
alembic_head=050_profile_name_encoding
stop_writers=$StopWriters
include_profiles_source=$IncludeProfilesSource
"@ | Out-File -Encoding utf8 (Join-Path $dest "manifest.txt")

    Get-Item (Join-Path $dest "postgres_secaudit.dump") | Format-List Name, Length, LastWriteTime
    Get-Item (Join-Path $dest "profiles_data.tar.gz") | Format-List Name, Length, LastWriteTime

    Write-Host ""
    Write-Host "Backup complete: $dest"
    Write-Host "Reminder: store .env / SECRET_KEY separately (encrypted). Never commit backups/."
    Write-Host "Runbook: docs/backup-restore-runbook.md"
}
finally {
    if ($stopped.Count -gt 0) {
        Write-Host "Starting api worker beat..."
        docker compose start api worker beat | Out-Null
    }
}
