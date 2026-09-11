# SecAudit — Getting started

Short guide to get a lab stack running. Full platform overview and deploy steps: [README.md](../../README.md).

---

## Quick start (Docker Compose)

```bash
cp .env.example .env
docker compose up -d --build
```

Open:

- UI: http://localhost:5173
- API docs: http://localhost:8000/docs
- Keycloak (dev): http://localhost:8080

Default lab stack uses Keycloak SSO (`AUTH_ENABLED=true`, `LOCAL_AUTH_ENABLED=false`). For local username/password login, set `LOCAL_AUTH_ENABLED=true` and configure bootstrap admin — see [secrets-howto.md](../secrets-howto.md).

---

## Core concepts

| Term | Meaning |
|------|---------|
| **Profile** | Compliance check package; API path `/api/v1/profiles` |
| **Job / Run** | Scheduled or manual compliance execution on hosts |
| **Remediation** | Fix scripts from profile packages |
| **Compliance playbook** | Optional Ansible YAML shipped with a profile |
| **Catalog** | On-disk packages under `./profiles` (mounted at `/profiles`) |

Profile package layout: [profiles/README.md](../../profiles/README.md).

---

## Production

Do **not** use lab defaults in production. Read:

- [production-guide.md](../production-guide.md) — deployment checklist
- [secrets-howto.md](../secrets-howto.md) — secrets management
- [ops-runbook.md](../ops-runbook.md) — operations
- [backup-restore-runbook.md](../backup-restore-runbook.md) — backup/restore
- [deploy/compose/README.md](../../deploy/compose/README.md) — Compose prod
- [deploy/helm/secaudit/README.md](../../deploy/helm/secaudit/README.md) — Helm

Key production settings:

- `APP_ENV=production`
- Unique `SECRET_KEY` (same on API + workers)
- `METRICS_BEARER_TOKEN` required
- `CONSOLE_ENABLED=false`
- Run migrations through the `migrate` service
- Persistent volume `profiles_data` for imported packages

---

## Further reading

| Topic | Link |
|-------|------|
| Overview + Compose / Helm | [README.md](../../README.md) |
| Profile structure + playbooks | [profiles/README.md](../../profiles/README.md) |
| Environment variables | [.env.example](../../.env.example) |

---

## API highlights

- `GET /api/v1/profiles` — imported profiles
- `GET /api/v1/profiles/catalog` — catalog from the `/profiles` mount
- `POST /api/v1/profiles/{id}/sync` — re-import from catalog source
- `POST /api/v1/profiles/bulk/{enable|disable|delete|sync}` — bulk actions

Swagger: `/docs` when the API is running.
