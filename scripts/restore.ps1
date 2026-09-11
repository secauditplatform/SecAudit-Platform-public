# SecAudit restore wrapper (Compose lab). Destructive — use on drill/DR only.
# Usage (from repo root):
#   .\scripts\restore.ps1 -BackupDir backups\backup_20250720_140000
#   .\scripts\restore.ps1 -BackupDir backups\backup_20250720_140000 -SkipPostgres
#   .\scripts\restore.ps1 -BackupDir backups\backup_20250720_140000 -Force

param(
    [Parameter(Mandatory = $true)]
    [string]$BackupDir,

    [switch]$SkipPostgres,
    [switch]$SkipProfilesData,
    [switch]$Force
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $BackupDir)) {
    throw "Backup directory not found: $BackupDir"
}

$pgDump = Join-Path $BackupDir "postgres_secaudit.dump"
$profilesTar = Join-Path $BackupDir "profiles_data.tar.gz"

if (-not $SkipPostgres -and -not (Test-Path $pgDump)) {
    throw "Missing postgres dump: $pgDump"
}
if (-not $SkipProfilesData -and -not (Test-Path $profilesTar)) {
    throw "Missing profiles archive: $profilesTar"
}

Write-Host "=== SecAudit RESTORE from $BackupDir ==="
Write-Host "This will overwrite PostgreSQL data and/or profiles_data volume."
if (-not $Force) {
    $answer = Read-Host "Type RESTORE to continue"
    if ($answer -ne "RESTORE") {
        Write-Host "Aborted."
        exit 1
    }
}

function Get-ProfilesVolumeName {
    $vol = docker volume ls -q --filter name=profiles_data | Select-Object -First 1
    if (-not $vol) {
        throw "Docker volume matching 'profiles_data' not found."
    }
    return $vol
}

Write-Host "Stopping api worker beat frontend..."
docker compose stop api worker beat frontend | Out-Null

try {
    if (-not $SkipPostgres) {
        Write-Host "Restoring PostgreSQL from $pgDump ..."
        docker compose cp $pgDump postgres:/tmp/restore.dump
        docker compose exec postgres pg_restore -U secaudit -d secaudit `
            --clean --if-exists --no-owner --role=secaudit -v /tmp/restore.dump
        if ($LASTEXITCODE -ne 0) {
            Write-Warning "pg_restore exited with code $LASTEXITCODE (warnings may be OK on re-restore)"
        }
        docker compose exec postgres rm -f /tmp/restore.dump | Out-Null
    }

    if (-not $SkipProfilesData) {
        $vol = Get-ProfilesVolumeName
        Write-Host "Restoring volume $vol from profiles_data.tar.gz ..."
        $backupAbs = (Resolve-Path $BackupDir).Path
        docker run --rm `
            -v "${vol}:/data" `
            -v "${backupAbs}:/backup:ro" `
            alpine sh -c "rm -rf /data/* /data/.[!.]* 2>/dev/null; tar xzf /backup/profiles_data.tar.gz -C /data"
    }

    Write-Host "Running migrations..."
    docker compose run --rm migrate

    Write-Host "Starting stack..."
    docker compose up -d

    Write-Host ""
    Write-Host "Restore finished. Verify:"
    Write-Host "  docker compose exec api alembic current"
    Write-Host "  .\scripts\ops_check.ps1"
    Write-Host "  docs/backup-restore-runbook.md §5"
    Write-Host ""
    Write-Host "Ensure .env SECRET_KEY matches the backup environment."
}
catch {
    Write-Error $_
    exit 1
}
