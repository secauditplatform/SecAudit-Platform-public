# SecAudit Helm chart

Kubernetes deployment for SecAudit API, Celery worker/beat, and nginx frontend.

## Expectations

- **External** PostgreSQL, Redis (with AUTH), and Keycloak
- Container images published as `secaudit/api`, `secaudit/worker`, `secaudit/frontend`
- Non-root UID `1000` (matches Dockerfiles)

## Install

```bash
helm lint deploy/helm/secaudit

helm upgrade --install secaudit deploy/helm/secaudit \
  --namespace secaudit --create-namespace \
  --set secrets.secretKey="$(openssl rand -hex 32)" \
  --set secrets.postgresPassword='...' \
  --set secrets.redisPassword='...' \
  --set secrets.metricsBearerToken="$(openssl rand -hex 24)" \
  --set secrets.secretsFernetAllowedInProduction=true \
  --set externalDatabase.host=postgres.db.svc \
  --set externalRedis.host=redis.cache.svc \
  --set config.keycloakUrl=https://keycloak.example.com \
  --set config.keycloakIssuer=https://keycloak.example.com/realms/secaudit \
  --set config.corsOrigins=https://secaudit.example.com \
  --set config.frontendBaseUrl=https://secaudit.example.com
```

Prefer `--set-file` / `existingSecret` for credentials in real environments.

### existingSecret keys

| Key | Purpose |
|-----|---------|
| `SECRET_KEY` | App signing / crypto |
| `POSTGRES_PASSWORD` | DB password |
| `REDIS_PASSWORD` | Redis AUTH |
| `METRICS_BEARER_TOKEN` | `/metrics` protection |
| `REDIS_URL` | Full broker URL including password |
| `CELERY_BROKER_URL` | Celery broker |
| `CELERY_RESULT_BACKEND` | Celery results |
| `SECRETS_FERNET_ALLOWED_IN_PRODUCTION` | `true` only during Fernet migration |

## Components

| Workload | Notes |
|----------|-------|
| `*-migrate-*` | Helm pre-install/pre-upgrade Job (`alembic upgrade head`) |
| `*-api` | FastAPI, `SKIP_MIGRATIONS=1` |
| `*-worker` | Celery queues from `worker.queues`; needs ICMP (`iputils-ping`) if network playbooks use ping |
| `*-beat` | Single replica (`Recreate`) |
| `*-frontend` | nginx SPA; proxies `/api` to in-cluster API Service |

## Related

- Compose prod: [deploy/compose](../../compose)
- Guide: [docs/production-guide.md](../../../docs/production-guide.md)
