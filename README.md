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

## What's new in v1.7.0

- **AAG is advisory** — AI Audit Generation is its own navigation group. The model explains a finished check or drafts a custom profile. It does not write check results, start a job, or start remediation.
- **One working provider** — the administrator saves an internal model or an external HTTPS API and turns the contour on for the selected row. The key is stored encrypted and is never shown back. While the contour is off, every saved provider stays offline. A call can wait up to 120 minutes.
- **Explain a finished run** — the operator picks FAIL or ERROR rows. A factual sentence cites the run and the rule, and a sentence without a citation is marked. The same completed request is served again from the saved result. A failed request can be run again.
- **Custom profile from a prompt** — Generate checks the package with the same validator as import. A valid package joins the profile list as `custom`. An existing name is not overwritten, and no job starts. Official CIS, STIG, and FSTEC names are rejected. A failed generation can be run again.

## What's new in v1.6.0

- **One IPv6 address is a scan target** — a single IPv6 address, or a hostname that resolves to AAAA, reaches nmap, SSH/WinRM, and the report as an address. An IPv6 prefix is rejected in the UI.
- **AuditFlow templates follow the inventory** — a template stores a tag and site rule. Each run uses the hosts that match now, and a host already covered by a written CIDR or the same SSH fingerprint is not added twice.
- **Customer CVE notes beside FAIL** — a customer CVE feed can sit next to a failed check. The check status does not change, and SecAudit does not scan package versions or keep its own CVE database.
- **Console token stays out of the URL** — the sandbox console sends the JWT in the `Authorization` header.

## What's new in v1.5.0

- **Audit Map** — one inventory view of checked hosts and services, as a map, a list, or a diagram, cut by network, ports, platform, and profile. Node color is the latest check result.
- **Hosts grouped by profile** — the map groups hosts by the profile of the latest check, and the host card names that profile.
- **Bulk host classification** — set site, environment, and criticality on the selected hosts. An empty field does not wipe a value already stored.
- **Failed inventory scans stay visible** — a failed nmap or SNMP scan is a Celery task error, with retry and the dead-letter queue.

## What's new in v1.4.0

- **SNMP inventory discovery** — SNMPv2c community and SNMPv3 use the same targets and the same host list as nmap. The AuditFlow wizard stays nmap-only.
- **Local MFA and API keys** — TOTP on local login, and scoped service-account API keys for automation.
- **Richer discovery** — AD/LDAP computer sync, SNMP probes, AuditFlow templates, and profile match hints.
- **Inventory context** — site, environment, and criticality on hosts, plus CSV import.
- **Safer change** — waiver change tickets, and Ansible check mode before a live playbook run.
- **Telegram notifications** — a delivery channel next to webhook and email.
- **Run evidence** — each job run keeps a snapshot of the profile that actually executed.

## What's new in v1.3.0

- **CSV host import** — import hosts from a CSV file after a preview of what will be written.
- **Evidence pack** — the run ZIP carries a signed pack: profile snapshot, waivers, sha256 hashes, and `manifest.sha256`.
- **Secrets stay out of AuditFlow live logs** — credentials are redacted in the live log stream.
- **Hard WinRM cancel** — cancelling a run stops the remote PowerShell process.
- **Every shipped locale is filled** — UI strings are translated in all twelve locales.

## What's new in v1.2.0

- **Directory inventory** — import computer objects from AD and LDAP into the same inventory as nmap.
- **Telegram notifications** — Telegram is a notification channel.
- **Scoped API keys** — service-account keys (`sa_*`) for CI/CD, limited by scope.
- **Playbook check mode** — Ansible `--check --diff` on playbook runs.
- **AuditFlow drift** — see which hosts appeared or disappeared between scans, with match-confidence hints and a closed-FAIL view.

## What's new in v1.1.0

- **AuditFlow templates** — save a discovery run, pull current inventory hosts into a one-shot target list, and schedule it.
- **Local TOTP MFA** — authenticator-app MFA for local accounts.
- **Role-based scan limits** — operators and admins have different maximum CIDR sizes.
- **Report packs and host metadata** — richer report packages, the waiver workflow, and host site, environment, and criticality.
- **Demo stand** — a guest demo mode with its own login and idle session limits.

## What's new in v1.0.0

v1.0.0 is the first numbered platform release: the on-prem compliance cycle in one UI.

- **Compliance cycle** — import profiles, run checks over SSH, WinRM, Ansible, Python, OpenSCAP, and Netmiko, then report, remediate, and re-audit.
- **AuditFlow** — scan a range, fingerprint the OS, match a profile, and run the selected checks.
- **Reports** — HTML, PDF, and CSV, plus drift, diff, compare, and trends.
- **On-prem stack** — FastAPI, Celery, PostgreSQL, Redis, React, and Keycloak in Docker Compose.

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
