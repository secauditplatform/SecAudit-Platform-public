# SecAudit Platform

On-prem platform for infrastructure **compliance audit and remediation**.

SecAudit helps security and infrastructure teams run the full cycle:

**Import profiles → discover hosts (AuditFlow) → run checks → report → remediate → re-audit**

Linux, Windows, and network devices are supported over SSH, WinRM, Ansible, Python, OpenSCAP, and Netmiko.

## Features

- **Compliance jobs** — scheduled or on-demand checks with live logs
- **AuditFlow** — nmap discovery, OS fingerprinting, profile match, selected checks
- **Profiles** — custom packages (`description.json` + `profile_rules.json`) and SCAP/XCCDF/OVAL import
- **Remediation** — profile scripts and network CLI/config download
- **Reports** — HTML / PDF / CSV, drift, diff, compare, waivers, trends
- **Playbooks** — Ansible for Linux / Windows / Network
- **Security** — Keycloak OIDC or local users, RBAC, encrypted credentials, audit log, SIEM export

## Stack

FastAPI · Celery · PostgreSQL 16 · Redis · React · Keycloak · Docker Compose / Helm

## Repository layout

| Path | Role |
|------|------|
| `api/` | FastAPI application and Alembic migrations |
| `workers/` | Celery workers (compliance, remediation, inventory, …) |
| `frontend/` | React web UI |
| `packages/secaudit_core/` | Shared Python library |
| `deploy/` | Production Compose and Helm chart |
| `infra/` | Lab Keycloak realm, Redis Sentinel, observability |
| `docs/` | Operations and production guides |
| `profiles/` | Catalog mount point (packages not shipped here) |

## Requirements

- Docker Engine 24+ with Compose v2 (or Kubernetes + Helm 3 for the chart)
- ~4 GB RAM for the lab stack

## Profiles directory

Compliance packages are **not** shipped in this repository. Keep the `profiles/` folder (see [profiles/README.md](profiles/README.md)) and place profile packages there, or point `PROFILES_SOURCE_PATH` at your catalog.

## Quick start (lab Docker Compose)

Development / demo topology from the repository root (includes Keycloak `start-dev`, hot-reload frontend, Redis Sentinel):

```bash
git clone https://github.com/secauditplatform/SecAudit-Platform.git
cd SecAudit-Platform
cp .env.example .env
docker compose up --build
```

| URL | Purpose |
|-----|---------|
| http://localhost:5173 | Web UI |
| http://localhost:8000/docs | API (Swagger) |
| http://localhost:8080 | Keycloak Admin |

Default Keycloak SSO users in the **lab** realm (`infra/keycloak/secaudit-realm.json`): `admin` / `admin` and `dev` / `dev`. That realm uses open redirect URIs and is **not** for production or public exposure.

Optional first **local** admin (DB users), when `LOCAL_AUTH_ENABLED=true`:

```env
LOCAL_AUTH_ENABLED=true
BOOTSTRAP_ADMIN_USERNAME=platform-admin
BOOTSTRAP_ADMIN_PASSWORD=replace-with-a-strong-password
```

Remove `BOOTSTRAP_ADMIN_*` after the first login. Full variable list: [.env.example](.env.example).

> Lab Compose is for demos and development. For production use the paths below.

## Production Docker Compose

Standalone production stack under [`deploy/compose`](deploy/compose) (do **not** mix with the root lab `docker-compose.yml`):

```bash
cd deploy/compose
cp .env.production.example .env
# Edit .env — set every required secret / URL

docker compose -f docker-compose.prod.yml --env-file .env up -d --build
```

- UI: `http://<host>:8080` (or `FRONTEND_PUBLISH_PORT`)
- API health: `http://127.0.0.1:8000/api/v1/health/live`
- Scale workers: `docker compose -f docker-compose.prod.yml --env-file .env up -d --scale worker=3` (keep a **single** `beat`)

Details: [deploy/compose/README.md](deploy/compose/README.md) · [docs/production-guide.md](docs/production-guide.md)

## Helm (Kubernetes)

Chart: [`deploy/helm/secaudit`](deploy/helm/secaudit)

Expects **external** PostgreSQL, Redis (with AUTH), and Keycloak, plus published images (`secaudit/api`, `secaudit/worker`, `secaudit/frontend`).

```bash
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

Full chart options: [deploy/helm/secaudit/README.md](deploy/helm/secaudit/README.md) · [docs/production-guide.md](docs/production-guide.md)

## Documentation

All operator guides are in English.

| Document | Description |
|----------|-------------|
| [profiles/README.md](profiles/README.md) | Profile package layout, rules, playbooks |
| [docs/en/getting-started.md](docs/en/getting-started.md) | Getting started |
| [docs/production-guide.md](docs/production-guide.md) | Lab vs production, smoke checks |
| [docs/demo-stand-deploy.md](docs/demo-stand-deploy.md) | Locked-down public demo stand |
| [deploy/compose/README.md](deploy/compose/README.md) | Production Compose |
| [deploy/helm/secaudit/README.md](deploy/helm/secaudit/README.md) | Helm install and secrets |
| [docs/ops-runbook.md](docs/ops-runbook.md) | Operations |
| [docs/secrets-howto.md](docs/secrets-howto.md) | Secrets and bootstrap |
| [docs/backup-restore-runbook.md](docs/backup-restore-runbook.md) | Backup and restore |
| [SECURITY.md](SECURITY.md) | Vulnerability reporting |

## Security

To report a vulnerability, see [SECURITY.md](SECURITY.md). Do not file public issues for security bugs.

## License

Copyright 2026 secauditplatform@proton.me.

Licensed under the [PolyForm Noncommercial License 1.0.0](LICENSE). Commercial use requires a separate license. See [NOTICE](NOTICE).
