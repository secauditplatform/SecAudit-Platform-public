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

- **End-to-end compliance cycle** — profiles → discovery (AuditFlow) → jobs → reports → remediation → re-audit.
- **Multi-platform checks** — Linux, Windows, and network devices from a single control plane.
- **Profile packages** — custom catalogs (`description.json` + `profile_rules.json`) and SCAP / XCCDF / OVAL import.
- **AuditFlow** — nmap discovery, OS fingerprinting, profile match, and selective launch.
- **Remediation** — packaged fix scripts and network CLI / config download.
- **Reporting** — HTML / PDF / CSV, drift, diff, compare, waivers, and trends.
- **Playbooks** — Ansible for Linux, Windows, and network scopes.
- **Enterprise auth & RBAC** — Keycloak OIDC or local users, object-level ownership, encrypted credentials, audit log, SIEM export.
- **Deploy your way** — lab Docker Compose for development; production Compose or Helm for real environments.

# Architecture

SecAudit follows a classic API + worker split on top of PostgreSQL and Redis:

| Layer | Components |
|-------|------------|
| UI | React SPA |
| Control plane | FastAPI (REST / WebSocket), Alembic migrations |
| Execution | Celery workers (compliance, remediation, inventory, maintenance) + beat |
| Data | PostgreSQL 16, Redis (broker / cache / locks) |
| Identity | Keycloak (OIDC) and/or local DB users |
| Shared library | `packages/secaudit_core` used by API and workers |

```text
┌────────────┐     ┌────────────┐     ┌─────────────────────────┐
│  Frontend  │────▶│    API     │────▶│  PostgreSQL · Redis     │
└────────────┘     └─────┬──────┘     └─────────────────────────┘
                         │ enqueue
                         ▼
                  ┌────────────┐     ┌─────────────────────────┐
                  │   Worker   │────▶│  SSH / WinRM / Ansible  │
                  │  (+ beat)  │     │  OpenSCAP / Netmiko     │
                  └────────────┘     └─────────────────────────┘
```

# Repository layout

| Path | Role |
|------|------|
| `api/` | FastAPI application and Alembic migrations |
| `workers/` | Celery workers |
| `frontend/` | React web UI |
| `packages/secaudit_core/` | Shared Python library |
| `deploy/` | Production Compose and Helm chart |
| `infra/` | Lab Keycloak realm, Redis Sentinel, observability |
| `docs/` | Operations and production guides |
| `profiles/` | Catalog mount point (packages are not shipped here) |

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
