# SecAudit — production Docker Compose

Standalone production stack. **Do not** combine this file with the lab root `docker-compose.yml`.

## Prerequisites

- Docker Engine 24+ with Compose v2
- External Keycloak (realm `secaudit`, clients `secaudit-frontend` / audience `secaudit-api`)
- Filled secrets in `deploy/compose/.env` (never commit it)

## Quick start

```bash
cd deploy/compose
cp .env.production.example .env
# edit .env — every ${VAR:?…} value must be set

docker compose -f docker-compose.prod.yml --env-file .env up -d --build
```

UI: `http://<host>:8080` (or `FRONTEND_PUBLISH_PORT`).  
API (loopback by default): `http://127.0.0.1:8000/api/v1/health/live`.

## What this stack enforces

| Lab compose | Prod compose |
|-------------|--------------|
| Keycloak `start-dev` | External IdP only |
| Redis without password | Redis `requirepass` |
| Grafana anonymous Admin | Grafana login (observability profile) |
| Vite hot-reload + bind mounts | Built nginx image, no source mounts |
| Default secrets | Fail-closed `${VAR:?required}` |
| Console on | `CONSOLE_ENABLED=false` |

## Scale workers

```bash
docker compose -f docker-compose.prod.yml --env-file .env up -d --scale worker=3
```

Keep a **single** `beat` replica. Worker image includes `iputils-ping` for network playbook ICMP checks.

## Observability (optional)

```bash
docker compose -f docker-compose.prod.yml --env-file .env --profile observability up -d
```

Requires `GF_SECURITY_ADMIN_USER` and `GF_SECURITY_ADMIN_PASSWORD` in `.env`. Anonymous Grafana admin is disabled.

## Migrations

The `migrate` one-shot service runs `alembic upgrade head` before API/worker start. For multi-host deploys, run migrate once, then set `SKIP_MIGRATIONS=1` on API replicas (already set on the `api` service).

## Secrets backends

`SECRETS_BACKEND=fernet` needs `SECRETS_FERNET_ALLOWED_IN_PRODUCTION=true` (migration opt-in). Prefer `vault` or `aws_kms` for sustained production — see [docs/secrets-howto.md](../../docs/secrets-howto.md).

## Related

- [docs/production-guide.md](../../docs/production-guide.md)
- Helm chart: [deploy/helm/secaudit](../helm/secaudit)
