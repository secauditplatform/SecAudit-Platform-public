# Getting started

Bring up a **lab** stack for development. Production: [production-guide.md](../production-guide.md). Overview: [README.md](../../README.md).

## Lab Compose

```bash
cp .env.example .env
docker compose up -d --build
```

| URL | Purpose |
|-----|---------|
| http://localhost:5173 | Web UI |
| http://localhost:8000/docs | API (Swagger) |
| http://localhost:8080 | Keycloak (dev) |

Default lab auth is Keycloak SSO (`AUTH_ENABLED=true`, `LOCAL_AUTH_ENABLED=false`). For local username/password, set `LOCAL_AUTH_ENABLED=true` and a bootstrap admin — see [secrets-howto.md](../secrets-howto.md).

Lab Keycloak users: `admin` / `admin`, `dev` / `dev`. Do not reuse this realm in production.

## Core concepts

| Term | Meaning |
|------|---------|
| **Profile** | Compliance package (`/api/v1/profiles`) |
| **Job / Run** | Scheduled or manual check on hosts |
| **Remediation** | Fix scripts from the profile package |
| **Catalog** | On-disk packages under `./profiles` → `/profiles` |

Package layout: [profiles/README.md](../../profiles/README.md). Env reference: [.env.example](../../.env.example).

## Next steps

- Import a profile from the catalog, add hosts, run a job.
- Production checklist: [production-guide.md](../production-guide.md)
- Secrets: [secrets-howto.md](../secrets-howto.md)
- Operations: [ops-runbook.md](../ops-runbook.md)
- Backup: [backup-restore-runbook.md](../backup-restore-runbook.md)
