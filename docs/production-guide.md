# SecAudit — Production deployment guide

Practical checklist for deploying SecAudit in **production**. The lab [`docker-compose.yml`](../docker-compose.yml) is for development only; for production use one of the two paths below.

See also:

- [ops-runbook.md](ops-runbook.md) — incidents, health, stuck runs
- [backup-restore-runbook.md](backup-restore-runbook.md) — PostgreSQL backup and the `profiles_data` volume
- [secrets-howto.md](secrets-howto.md) — secrets management
- [deploy/compose/README.md](../deploy/compose/README.md) — Compose prod quick start
- [deploy/helm/secaudit/README.md](../deploy/helm/secaudit/README.md) — Helm chart

---

## Lab vs production

| | Lab (`docker-compose.yml`) | Production |
|--|----------------------------|------------|
| Manifest | Root Compose | [`deploy/compose/docker-compose.prod.yml`](../deploy/compose/docker-compose.prod.yml) or [`deploy/helm/secaudit`](../deploy/helm/secaudit) |
| `APP_ENV` | `development` | `production` |
| Keycloak | `start-dev` in Compose | External IdP (`KEYCLOAK_URL` / issuer); no `start-dev` |
| Redis | Sentinel HA, **no AUTH** | AUTH (`requirepass` / managed Redis password); TLS/Sentinel HA — follow-up / managed |
| Grafana | Anonymous Admin | Login required (`GF_AUTH_ANONYMOUS_ENABLED=false`); set `GF_SECURITY_ADMIN_PASSWORD` explicitly (do not use a default such as `changeme`), or omit the observability profile |
| Frontend | Vite HMR + bind-mount | nginx SPA image (`8080`) |
| Worker / API | Bind-mount / reload | Immutable images; API/worker/frontend **non-root UID 1000** |
| Secrets | Defaults in `.env.example` | Fail-closed `${VAR:?required}` / Helm `existingSecret` |

---

## Path A — Compose prod (single-node / VM)

```bash
cp deploy/compose/.env.production.example deploy/compose/.env
# fill SECRET_KEY, POSTGRES_PASSWORD, REDIS_PASSWORD, METRICS_BEARER_TOKEN,
# KEYCLOAK_*, CORS_ORIGINS, FRONTEND_BASE_URL, SECRETS_FERNET_ALLOWED_IN_PRODUCTION
# If using --profile observability: set GF_SECURITY_ADMIN_PASSWORD explicitly

docker compose -f deploy/compose/docker-compose.prod.yml --env-file deploy/compose/.env config
docker compose -f deploy/compose/docker-compose.prod.yml --env-file deploy/compose/.env up -d --build
```

Optional Grafana/Prometheus/Tempo:

```bash
docker compose -f deploy/compose/docker-compose.prod.yml --env-file deploy/compose/.env \
  --profile observability up -d
```

When enabling the observability profile, set a strong `GF_SECURITY_ADMIN_PASSWORD` in `.env` before `up`. Do not rely on any default password.

- `postgres` / `redis` are **not** published on the host (internal network only).
- One-shot `migrate` runs `alembic upgrade head` before API.
- API uses `SKIP_MIGRATIONS=1`, uvicorn **without** `--reload`.
- Frontend: `8080:8080` (nginx).

Smoke:

```bash
curl http://localhost:8080/api/v1/health/live
curl http://localhost:8080/api/v1/health/ready
docker compose -f deploy/compose/docker-compose.prod.yml --env-file deploy/compose/.env ps
```

---

## Path B — Helm (Kubernetes)

Defaults: **BYO** PostgreSQL, Redis (with AUTH), Keycloak. Replicas: api=2, worker=2, beat=1. Non-root `runAsUser: 1000`.

```bash
helm lint deploy/helm/secaudit

helm upgrade --install secaudit deploy/helm/secaudit \
  --namespace secaudit --create-namespace \
  --set existingSecret=secaudit-secrets \
  --set externalDatabase.host=postgres.db.svc \
  --set externalRedis.host=redis.cache.svc \
  --set config.keycloakUrl=https://keycloak.example.com \
  --set config.keycloakIssuer=https://keycloak.example.com/realms/secaudit \
  --set config.corsOrigins=https://secaudit.example.com \
  --set config.frontendBaseUrl=https://secaudit.example.com
```

Migrations: Helm pre-install/pre-upgrade Job (`alembic upgrade head`). API Deployments set `SKIP_MIGRATIONS=1`.

Prefer `existingSecret` over putting passwords in values. Required secret keys are listed in the [chart README](../deploy/helm/secaudit/README.md).

---

## 1. Before go-live

| Step | Action |
|------|--------|
| 1 | Choose path A (Compose) or B (Helm); do **not** use the root lab Compose |
| 2 | Set `APP_ENV=production` (already set in prod manifests) |
| 3 | Generate a unique `SECRET_KEY` (`openssl rand -hex 32`) — **same** value on `api` and `worker` |
| 4 | Set strong PostgreSQL and Redis passwords |
| 5 | Configure Keycloak in production mode (not `start-dev`) |
| 6 | Decide: `LOCAL_AUTH_ENABLED=true` or Keycloak only |
| 7 | Set `METRICS_BEARER_TOKEN` (otherwise `/api/v1/metrics` returns 503) |
| 8 | Keep `CONSOLE_ENABLED=false` |
| 9 | Verify CORS (`CORS_ORIGINS`) and `FRONTEND_BASE_URL` |
| 10 | Persist `/data/profiles` (Compose volume / Helm PVC) |

---

## 2. Authentication

### Keycloak (recommended for enterprise)

- Lab Compose: `start-dev --import-realm` — **not for production**.
- Production: dedicated Keycloak, realm `secaudit`, clients `secaudit-frontend` / audience `secaudit-api`.
- Variables:
  - `KEYCLOAK_URL` — JWKS **from inside** the network
  - `KEYCLOAK_ISSUER` — public issuer (as the browser sees it)
  - `KEYCLOAK_REALM`, `KEYCLOAK_CLIENT_ID`, `KEYCLOAK_AUDIENCE`
- Store the client secret in a secret manager — see [secrets-howto.md](secrets-howto.md).

### Local auth + bootstrap admin

- `LOCAL_AUTH_ENABLED=true` — username/password login from the `users` table.
- The first admin is created **only when the users table is empty**, via:
  - `BOOTSTRAP_ADMIN_USERNAME` / `BOOTSTRAP_ADMIN_PASSWORD`, or
  - `BOOTSTRAP_ADMIN_PASSWORD_FILE` (preferred in prod)
- After the first login, **remove** the bootstrap variables.
- Placeholder passwords (`dev`, `admin`, `password`, …) are rejected by the validator.

### Dev-only mode

- `AUTH_ENABLED=false` issues a synthetic admin — **forbidden in production**.

---

## 3. Database migrations

1. Compose prod: `migrate` service → `alembic upgrade head` **before** `api` starts.
2. Helm: pre-install/pre-upgrade Job; API with `SKIP_MIGRATIONS=1`.
3. Verify (Compose):

```powershell
docker compose -f deploy/compose/docker-compose.prod.yml --env-file deploy/compose/.env run --rm migrate alembic current
```

---

## 4. Profiles and volumes

| Volume / mount | Path in container | Purpose |
|----------------|-------------------|---------|
| Host / ConfigMap profiles (optional) | `/profiles:ro` | Discover/sync source |
| `profiles_data` / PVC | `/data/profiles` | Persistent imported packages |

- `PROFILES_PATH=/profiles`
- `PROFILES_STORAGE_PATH=/data/profiles`
- `PROFILES_AUTO_SEED=false` is typical in prod

Backup — [backup-restore-runbook.md](backup-restore-runbook.md).

---

## 5. Redis and Celery

- Lab Compose: Redis Sentinel HA **without a password**.
- Compose prod: standalone Redis with `requirepass` + AOF; URLs include the password.
- Helm / managed: `REDIS_URL`, `CELERY_BROKER_URL`, `CELERY_RESULT_BACKEND` with AUTH (and TLS on managed).
- Queues: `compliance`, `remediation`, `inventory`, `maintenance`.

---

## 6. Observability and security hardening

| Variable / component | Production |
|----------------------|------------|
| `METRICS_BEARER_TOKEN` | **Required** |
| `CONSOLE_ENABLED` | `false` |
| `SSH_STRICT_HOST_KEY_CHECKING` | `true` |
| `WINRM_SERVER_CERT_VALIDATION` | `validate` |
| Grafana | Login only (no anonymous Admin); set `GF_SECURITY_ADMIN_PASSWORD` explicitly — never ship or rely on a default such as `changeme` |

```powershell
curl -H "Authorization: Bearer $env:METRICS_BEARER_TOKEN" http://localhost:8080/api/v1/metrics
```

---

## 7. Multi-replica notes

- **Migrations:** one migrate job; API replicas with `SKIP_MIGRATIONS=1`.
- **Beat:** only **one** Celery beat instance.
- **Workers:** horizontal scaling; outbox/dispatch is idempotent.
- **profiles_data:** shared volume (RWX) or an object-storage strategy.
- Helm defaults: api=2, worker=2, beat=1.

---

## 8. Smoke checklist after deploy

```powershell
curl http://<host>:8080/api/v1/health/live
curl http://<host>:8080/api/v1/health/ready
```

- [ ] Login via Keycloak or bootstrap admin
- [ ] `GET /api/v1/profiles`
- [ ] Test compliance job + worker heartbeat
- [ ] Scheduled backup of PostgreSQL + profiles volume

---

## 9. Non-root images

| Image | UID |
|-------|-----|
| `api` | 1000 (`secaudit`) |
| `worker` | 1000 (`secaudit`) |
| `frontend` | 1000 (nginx on 8080) |

`/data/profiles` must be writable by UID 1000.

---

## Related documents

- [deploy/compose/README.md](../deploy/compose/README.md)
- [deploy/helm/secaudit/README.md](../deploy/helm/secaudit/README.md)
- [secrets-howto.md](secrets-howto.md)
- [ops-runbook.md](ops-runbook.md)
- [backup-restore-runbook.md](backup-restore-runbook.md)
- [en/getting-started.md](en/getting-started.md)
