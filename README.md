# SecAudit Platform

<p align="center">
  <strong>On-prem compliance audit and remediation for Linux, Windows, and network devices</strong>
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-PolyForm%20Noncommercial-blue.svg" alt="License"></a>
  <a href="SECURITY.md"><img src="https://img.shields.io/badge/security-policy-green.svg" alt="Security policy"></a>
  <a href="docs/en/getting-started.md"><img src="https://img.shields.io/badge/docs-getting%20started-informational.svg" alt="Getting started"></a>
</p>

**SecAudit Platform** is an on-premises product for infrastructure compliance: import check packages, discover hosts, run audits, report findings, remediate, and re-check — in one cycle.

It is built for security and infrastructure teams that need a controlled, auditable workflow instead of ad-hoc scripts. Targets are reached over SSH, WinRM, Ansible, Python, OpenSCAP, and Netmiko.

# Main features

- **Full compliance lifecycle** — discover assets, run checks, report findings, remediate, and verify again in one controlled workflow.
- **One control plane, many targets** — audit Linux, Windows, and network devices over SSH, WinRM, Ansible, OpenSCAP, and Netmiko.
- **Portable profile packages** — ship custom rule packs or import SCAP / XCCDF / OVAL content into a versioned catalog.
- **Guided discovery with AuditFlow** — map the network, fingerprint OS, match profiles, and launch only the checks you select.
- **Actionable remediation** — apply packaged fix scripts on hosts, or export network CLI / config for operator-driven change.
- **Evidence-ready reporting** — HTML, PDF, and CSV plus drift, diff, compare, waivers, and trend views for audits and reviews.
- **Automation with playbooks** — run Ansible playbooks across Linux, Windows, and network scopes from the same jobs model.
- **Security built in** — Keycloak OIDC or local users, object-level RBAC, encrypted credentials, audit trail, and SIEM export.
- **Production-ready packaging** — develop on lab Compose; deploy with hardened Compose or Helm on your infrastructure.

# Architecture

SecAudit separates the **control plane** (API, UI, identity) from **execution** (Celery workers). The API accepts work, persists state, and enqueues tasks; workers reach managed hosts and write results back. Shared domain logic lives in `secaudit_core` so API and workers stay consistent.


| Layer | Responsibility |
|-------|----------------|
| **Frontend** | Operator UI for jobs, hosts, profiles, reports, and settings |
| **API** | AuthZ, REST / WebSocket, scheduling hooks, migrations (Alembic) |
| **Workers** | Compliance, remediation, inventory, and maintenance queues; beat for periodic tasks |
| **Data store** | PostgreSQL for durable state; Redis for broker, locks, and short-lived keys |
| **Identity** | Keycloak OIDC and/or local DB users |
| **Shared core** | `packages/secaudit_core` — policies, executors helpers, notifications, egress controls |

# Repository layout

| Path | What you will find |
|------|--------------------|
| `api/` | FastAPI app, routers, and Alembic migrations |
| `workers/` | Celery app, task entrypoints, and host executors |
| `frontend/` | React SPA |
| `packages/secaudit_core/` | Shared library used by API and workers |
| `deploy/` | Production Docker Compose and Helm chart |
| `infra/` | Lab Keycloak realm, Redis Sentinel, observability configs |
| `docs/` | Getting started, production, ops, secrets, backup |
| `profiles/` | Mount point for your compliance catalog (packages are not shipped in-repo) |

# Getting started

Requirements: Docker Engine 24+ with Compose v2, about 4 GB RAM for the lab stack.

Compliance packages are **not** included in this repository. Keep the `profiles/` folder (see [profiles/README.md](profiles/README.md)) and place packages there, or set `PROFILES_SOURCE_PATH`.

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

Lab Keycloak users (`infra/keycloak/secaudit-realm.json`): `admin` / `admin` and `dev` / `dev`. That realm uses open redirect URIs and is **not** for production.

Optional first local admin when `LOCAL_AUTH_ENABLED=true`:

```env
LOCAL_AUTH_ENABLED=true
BOOTSTRAP_ADMIN_USERNAME=platform-admin
BOOTSTRAP_ADMIN_PASSWORD=replace-with-a-strong-password
```

Remove `BOOTSTRAP_ADMIN_*` after the first login. Full variable list: [.env.example](.env.example).

Step-by-step walkthrough: [docs/en/getting-started.md](docs/en/getting-started.md).

> The root Compose file is for local development only. For production use the paths below.

# Production

## Docker Compose

Standalone stack under [`deploy/compose`](deploy/compose) — do **not** mix with the root lab `docker-compose.yml`:

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

# Documentation

| Document | Description |
|----------|-------------|
| [docs/en/getting-started.md](docs/en/getting-started.md) | First lab bring-up |
| [docs/production-guide.md](docs/production-guide.md) | Production checklist (Compose / Helm) |
| [docs/ops-runbook.md](docs/ops-runbook.md) | Day-2 operations |
| [docs/secrets-howto.md](docs/secrets-howto.md) | Secrets and bootstrap |
| [docs/backup-restore-runbook.md](docs/backup-restore-runbook.md) | Backup and restore |
| [profiles/README.md](profiles/README.md) | Profile package layout |
| [deploy/compose/README.md](deploy/compose/README.md) | Production Compose |
| [deploy/helm/secaudit/README.md](deploy/helm/secaudit/README.md) | Helm install and secrets |
| [SECURITY.md](SECURITY.md) | Vulnerability reporting |

# Security

To report a vulnerability, see [SECURITY.md](SECURITY.md). Do not open public issues for security bugs.

# License

Copyright 2026 secauditplatform@proton.me.

Licensed under the [PolyForm Noncommercial License 1.0.0](LICENSE). Commercial use requires a separate license. See [NOTICE](NOTICE).
