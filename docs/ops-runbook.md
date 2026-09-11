# SecAudit — Support / Operations Runbook

Practical runbook for deploying and supporting a Compose stand.

**Do not invent endpoints:** every path below is a real `/api/v1/…` route.

---

## 0. Where to look (prerequisites)

### Compose services

| Service | Role | Port / notes |
|--------|------|----------------|
| `postgres` | Database | `5432` |
| Redis (broker) | Celery broker + heartbeat/keys | **Lab Compose:** `redis-master` / `redis-replica` + 3× Sentinel; master name `secaudit-master` (broker `/0`, results `/1`). **Prod Compose** (`deploy/compose/docker-compose.prod.yml`): standalone service named `redis` (no Sentinel; `REDIS_SENTINEL_HOSTS` empty). Lab may also run optional standalone `redis` via Compose profile `standalone`. |
| `migrate` | One-shot `alembic upgrade head` | Before `api` starts |
| `api` | REST / WS | `8000` |
| `worker` | Celery: `-Q compliance,remediation,inventory,maintenance` | — |
| `beat` | Schedules (sweeper, heartbeat, outbox, …) | — |
| `frontend` | UI | `5173` |
| `keycloak` | OIDC | `8080` (lab Compose; prod typically uses an external issuer) |

Volumes: `postgres_data`, **`profiles_data`** (`PROFILES_STORAGE_PATH=/data/profiles`), mount `./profiles` → `/profiles:ro`.  
Backup/restore (RPO/RTO, pg_dump, DR drill): **[backup-restore-runbook.md](backup-restore-runbook.md)**.

### Health / metrics

```powershell
# Liveness (no dependency checks)
curl http://localhost:8000/api/v1/health/live

# Readiness: postgres + redis + celery_broker + celery_workers (ping + heartbeat)
curl http://localhost:8000/api/v1/health/ready

# Metrics (in production METRICS_BEARER_TOKEN is required)
curl -H "Authorization: Bearer $env:METRICS_BEARER_TOKEN" http://localhost:8000/api/v1/metrics
# alternative: X-Observability-Token header
```

Readiness components: `postgres`, `redis`, `celery_broker`, `celery_workers`.  
With `READINESS_REDACT_DETAILS=true` (default), details collapse to phrases such as `worker heartbeat unhealthy` / `no workers available`.  
Readiness cache: `READINESS_CACHE_SECONDS` (default 5 s) — after a restart, wait a few seconds.

Quick diagnostics: [`scripts/ops_check.ps1`](../scripts/ops_check.ps1).

### Logs

```powershell
docker compose ps
docker compose logs -f --tail=200 api worker beat
docker compose logs --tail=100 migrate
```

### Redis keys (relevant)

| Key | Purpose |
|------|------------|
| `secaudit:worker:heartbeat:last_seen` | ISO timestamp of the last worker heartbeat (TTL ≈ `WORKER_HEARTBEAT_MAX_AGE_SECONDS`, default 120) |
| `secaudit:worker:heartbeat:alert_state` | `stale` / `ok` for edge-triggered notifications |
| `inventory_scan:{id}:cancel` | Inventory scan cancel flag |

```powershell
# Lab Compose (Sentinel):
docker compose exec redis-master redis-cli GET secaudit:worker:heartbeat:last_seen
docker compose exec redis-master redis-cli GET secaudit:worker:heartbeat:alert_state

# Prod Compose (standalone redis; add -a "$REDIS_PASSWORD" when auth is enabled):
docker compose exec redis redis-cli GET secaudit:worker:heartbeat:last_seen
docker compose exec redis redis-cli GET secaudit:worker:heartbeat:alert_state
```

### Code / timings (reference)

| Mechanism | Where | Period / threshold |
|----------|-----|----------------|
| Heartbeat task | `app.tasks.compliance.heartbeat` → `touch_worker_heartbeat` | beat every **60 s**, queue `compliance` |
| Heartbeat alert | `app.tasks.maintenance.check_worker_heartbeat` | **60 s**, queue `maintenance` |
| Stale sweeper | `app.tasks.maintenance.sweep_stale_runs` → `secaudit_core.stale_runs` | **300 s** |
| Stale RUNNING | `STALE_RUN_TIMEOUT_SECONDS` or `2 × CELERY_TASK_TIME_LIMIT` | default **7800 s** |
| Orphan PENDING | `PENDING_ORPHAN_TIMEOUT_SECONDS` or `min(600, max(120, soft_limit/4))` | default **600 s** |
| Sweeper messages | `STALE_RUN_ERROR_MESSAGE` / `PENDING_ORPHAN_ERROR_MESSAGE` | “Run timed out or worker lost” / “Run was never picked up by a worker” |

Cancel a run: `POST …/stop` → `cancel_active_run` (`api/app/services/dispatch.py`) → status `cancelled`, `error_message=Cancelled by user`, revoke Celery task.

OpenSCAP: `workers/app/executors/oscap_exec.py` — **`oscap` is checked on the target host over SSH**, not in the worker image.

---

## 1. Stuck / “frozen” run (compliance / remediation)

### Symptoms

- In UI/API the run stays in `pending` or `running` for a long time.
- After sweeper: `failed` with `error_message`:
  - `Run timed out or worker lost` — was `running`, worker lost / timeout;
  - `Run was never picked up by a worker` — remained `pending`.
- Notifications / webhook: `run_stale`, `dispatch_failed`.
- Live WS logs stopped; Celery task is not progressing.

### Diagnosis

```powershell
# Stack and worker health
.\scripts\ops_check.ps1
curl http://localhost:8000/api/v1/health/ready

# Execution logs
docker compose logs --tail=300 worker beat

# Active Celery tasks (from the worker container)
docker compose exec worker celery -A app.celery_app inspect active
docker compose exec worker celery -A app.celery_app inspect ping

# Outbox / heartbeat
# Lab Compose:
docker compose exec redis-master redis-cli LLEN compliance   # queue length depends on Redis backend; also check dispatch logs
docker compose exec redis-master redis-cli GET secaudit:worker:heartbeat:last_seen
# Prod Compose: use `docker compose exec redis redis-cli …` (and -a when password-protected)
```

Via API (JWT required: operator/engineer/admin):

```http
GET /api/v1/jobs/runs/{run_id}
GET /api/v1/remediations/runs/{run_id}
```

Check: `status`, `started_at`, `celery_task_id`, `error_message`.

Distinction:

| Status | Typical cause |
|--------|------------------|
| `pending` + no `celery_task_id` | outbox not delivered / no worker / beat `dispatch-outbox` |
| `pending` for a long time | queue not consumed; orphan → sweeper after ~10 min |
| `running` with no progress | SSH/oscap hang, worker killed, host unreachable |
| `failed` + stale message | sweeper already ran |

### Remediation

**1. Operator cancel (preferred):**

```http
POST /api/v1/jobs/runs/{run_id}/stop
POST /api/v1/remediations/runs/{run_id}/stop
POST /api/v1/inventory/scans/{scan_id}/stop
```

Roles: `operator` | `engineer` | `admin`.  
Only from `pending`/`running` (otherwise **409**).  
Code: `jobs.py` / `remediations.py` / `inventory.py` → `cancel_active_run` + `revoke_task`.

Inventory also sets Redis flag `inventory_scan:{id}:cancel`.

**2. If the worker is dead — bring worker/beat up first** (section 2), then cancel or wait for the sweeper.

**3. Do not kill Postgres.** Restarting the worker is safe: cancel/sweeper will move the run to a terminal status; re-running the job is a separate action.

**4. Wait for the sweeper** (up to `STALE_RUN_*`) if cancel is unavailable and the run is orphaned.

### Verification

```http
GET /api/v1/jobs/runs/{run_id}
```

Expected after stop: `status=cancelled`, `finished_at` set.  
After sweeper: `failed` + one of the messages above.  
A new run of the same job should reach `running`/`completed`.

---

## 2. Worker unavailable / unhealthy

### Symptoms

- `GET /api/v1/health/ready` → **503**, component `celery_workers` = `error`.
- Metrics: `secaudit_worker_heartbeat_stale 1`, `secaudit_worker_heartbeat_age_seconds -1` or a large value.
- Notification `worker_heartbeat_stale` (“Celery worker heartbeat is stale…”).
- Jobs stay in `pending`; `inspect ping` is empty.

### How the check works

1. Celery **inspect.ping** — whether live worker processes exist.
2. Redis heartbeat key is updated by the `heartbeat` task (queue **`compliance`**, every 60 s).
3. If ping is OK but heartbeat age > `WORKER_HEARTBEAT_MAX_AGE_SECONDS` (120) → readiness **error** (“ping ok, but heartbeat stale”).
4. If the key is missing → “heartbeat timestamp missing”.

**Quirk:** the heartbeat is written by the **worker**, but the task is enqueued by **beat** onto queue `compliance`. If the worker is not consuming `compliance` or beat is down — ping may still be OK (other queues) while the heartbeat is stale.

**Readiness quirk:** 5 s cache + redact — do not panic over a single “red” second right after restart.

### Diagnosis

```powershell
# Lab Compose (Sentinel):
docker compose ps worker beat redis-master redis-replica redis-sentinel-1 redis-sentinel-2 redis-sentinel-3
# Prod Compose:
docker compose ps worker beat redis

curl http://localhost:8000/api/v1/health/ready
docker compose logs --tail=200 worker beat

docker compose exec worker celery -A app.celery_app inspect ping
docker compose exec worker celery -A app.celery_app inspect stats

# Lab Compose:
docker compose exec redis-master redis-cli PING
docker compose exec redis-master redis-cli GET secaudit:worker:heartbeat:last_seen
docker compose exec redis-master redis-cli GET secaudit:worker:heartbeat:alert_state
# Prod Compose: docker compose exec redis redis-cli … (-a when password-protected)
```

| Observation | Conclusion |
|------------|--------|
| Redis / Sentinel unhealthy (lab) or `redis` unhealthy (prod) | broker unavailable — restore Redis (and Sentinel in lab) |
| ping empty | worker process is not listening to the broker |
| ping OK, heartbeat empty/stale | not consuming `compliance` **or** beat not sending heartbeat |
| only beat down | schedules (sweeper/outbox/heartbeat) are stopped |

### Remediation (safe order)

```powershell
# 1. Redis must be healthy
# Lab Compose:
docker compose up -d redis-master redis-replica redis-sentinel-1 redis-sentinel-2 redis-sentinel-3
docker compose exec redis-master redis-cli PING
# Prod Compose:
docker compose up -d redis
docker compose exec redis redis-cli PING   # add -a "$REDIS_PASSWORD" when required

# 2. Worker (queues compliance,…,maintenance)
docker compose up -d --build worker
# or soft restart:
docker compose restart worker

# 3. Beat (after or together with worker)
docker compose up -d beat
docker compose restart beat

# Scale if needed
docker compose up -d --scale worker=2
```

Do not delete the Redis volume unless necessary (loss of queues/metrics).  
Do not run `docker compose down -v` in production — it wipes `postgres_data` / `profiles_data`. Before DR see [backup-restore-runbook.md](backup-restore-runbook.md).

### Verification

```powershell
Start-Sleep -Seconds 70   # wait for at least one heartbeat
curl http://localhost:8000/api/v1/health/ready
# Lab: docker compose exec redis-master redis-cli GET secaudit:worker:heartbeat:last_seen
# Prod: docker compose exec redis redis-cli GET secaudit:worker:heartbeat:last_seen
```

Expected: `status=ok`, fresh ISO timestamp, and if a notification channel exists — `worker_heartbeat_recovered`.

---

## 3. Missing `oscap` (OpenSCAP)

### Where it is required

| Place | Is `oscap` needed? |
|-------|----------------|
| **worker** image (`workers/Dockerfile`) | **No** — OpenSCAP is not installed in the image |
| **api** image | No |
| **Target host** (SSH), SCAP/XCCDF/OVAL job | **Yes**, if the job uses the OpenSCAP executor |
| Profile with shell/Ansible checks only | No (fallback to scripts) |

Check on the target: `command -v oscap` (`workers/app/executors/oscap_exec.py` → `OscapNotAvailableError`).

Error text: *OpenSCAP (oscap) is not installed on the target host. Install open-scap-scanner or use a profile with embedded shell checks.*

### Symptoms

- In the job live log: warning with the text above.
- Results: `OSCAPI_ERROR` / empty merge; if an audit script exists — partial fallback.
- The job may finish with per-host errors, not necessarily a global crash.

### Diagnosis

```powershell
# On the target host (same user as in the credential)
ssh user@target 'command -v oscap && oscap --version'

# Worker logs during the run
docker compose logs --tail=200 worker | Select-String -Pattern "oscap|OpenSCAP|OSCAPI"
```

Confirm the job is SCAP/XCCDF/OVAL (not only custom shell) and that the host has a loaded benchmark (`scap_benchmark.xml` / OVAL content from the worker).

### Remediation (operator)

On the **target** OS (examples):

```bash
# RHEL / Alma / Rocky
sudo dnf install -y openscap-scanner

# Debian / Ubuntu (packages vary by distro)
sudo apt-get update && sudo apt-get install -y openscap-scanner
# or libopenscap8 / openscap-utils — whichever provides the oscap binary

command -v oscap && oscap --version
```

Alternative: use a profile with embedded shell checks / do not select a pure SCAP engine if oscap cannot be installed across the fleet.

### Verification

Re-run the compliance job on the same host. In the log — `OpenSCAP … returned N results`, without `OscapNotAvailableError`. In the report — pass/fail per rule, not `OSCAPI_ERROR`.

---

## 4. Related scenarios (brief)

### 4.1 API unavailable

```powershell
curl http://localhost:8000/api/v1/health/live    # is the process up?
curl http://localhost:8000/api/v1/health/ready   # dependencies?
docker compose logs --tail=200 api
docker compose ps migrate   # Exit 0? otherwise API may not have started (depends_on)
docker compose up -d api
```

`live` OK + `ready` 503 → fix PG/Redis/worker; do not “restart API blindly” in a loop.

### 4.2 Migrations / database

Current head: **`050_profile_name_encoding`**. Migration `029_rename_standards_to_profiles` historically renamed table `standards` → `profiles` and columns `standard_id` → `profile_id`.

```powershell
docker compose run --rm migrate
# or
docker compose exec api alembic current
docker compose exec api alembic upgrade head
docker compose exec postgres pg_isready -U secaudit -d secaudit
```

On rename errors against an already-upgraded DB — do not run `downgrade` without a backup. `SKIP_MIGRATIONS=1` on api is acceptable if the migrate service already applied head.

### 4.3 Empty profiles catalog after volume rename

After the move `standards_data` → **`profiles_data`** and `PROFILES_STORAGE_PATH=/data/profiles`, the old volume with packages is **not mounted**.

```powershell
docker compose exec api ls -la /data/profiles
docker compose exec api ls -la /profiles
curl -H "Authorization: Bearer <token>" http://localhost:8000/api/v1/profiles/discover
curl -H "Authorization: Bearer <token>" http://localhost:8000/api/v1/profiles
```

Actions: import via UI/API (`POST /api/v1/profiles/import`, bulk catalog), or copy data from the old volume onto `profiles_data`. Opt-in sync: `PROFILES_CATALOG_SYNC_ENABLED=true` + beat. Status: `GET /api/v1/profiles/catalog/sync-status`.

### 4.4 Auth / Keycloak (minimum)

- Lab Compose: Keycloak `http://localhost:8080`, realm `secaudit`.
- `KEYCLOAK_ISSUER` must match the JWT `iss` (often `http://localhost:8080/realms/secaudit`).
- Local auth: `LOCAL_AUTH_ENABLED`, `POST /api/v1/auth/local`, refresh — `POST /api/v1/auth/refresh`.
- Stop/cancel require role operator+ and a valid Bearer token.

---

## 5. Command cheat sheet

```powershell
# Status
docker compose ps
.\scripts\ops_check.ps1

# Restart execution plane
docker compose restart worker beat

# Migrations
docker compose run --rm migrate

# Heartbeat
# Lab Compose:
docker compose exec redis-master redis-cli GET secaudit:worker:heartbeat:last_seen
# Prod Compose:
docker compose exec redis redis-cli GET secaudit:worker:heartbeat:last_seen

# Celery
docker compose exec worker celery -A app.celery_app inspect ping
docker compose exec worker celery -A app.celery_app inspect active
```

Cancel a run (after obtaining a token):

```powershell
$headers = @{ Authorization = "Bearer $token" }
Invoke-RestMethod -Method Post -Uri "http://localhost:8000/api/v1/jobs/runs/$runId/stop" -Headers $headers
Invoke-RestMethod -Method Post -Uri "http://localhost:8000/api/v1/remediations/runs/$runId/stop" -Headers $headers
```

---

## Code references

| Topic | Path |
|------|------|
| Cancel run | `api/app/services/dispatch.py` (`cancel_active_run`) |
| Stop endpoints | `api/app/api/v1/routers/jobs.py`, `remediations.py`, `inventory.py` |
| Stale sweeper | `packages/secaudit_core/secaudit_core/stale_runs.py`, `workers/app/tasks/maintenance.py` |
| Heartbeat | `packages/secaudit_core/secaudit_core/celery_observability.py`, `workers/app/tasks/compliance.py` |
| Readiness | `api/app/services/health_checks.py`, `api/app/api/v1/routers/health.py` |
| OpenSCAP executor | `workers/app/executors/oscap_exec.py` |
| Profiles API | `api/app/api/v1/routers/profiles.py` (`/api/v1/profiles`) |
| Beat schedule | `workers/app/celery_app.py` |
| Env defaults | `.env.example` (`STALE_RUN_*`, `WORKER_HEARTBEAT_*`, `PROFILES_*`, `METRICS_BEARER_TOKEN`) |
