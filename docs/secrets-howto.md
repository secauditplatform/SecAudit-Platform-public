# SecAudit — Howto: managing secrets

Short guide to platform secrets. The source of truth for variables is [`.env.example`](../.env.example).

**Rule:** never commit `.env`, password files, private keys, Keycloak client secrets, or metrics/S3/SMTP tokens.

---

## 1. What counts as a secret

| Secret | Variable / location | Where it is used |
|--------|---------------------|------------------|
| API/worker signing key | `SECRET_KEY` | JWT local auth, Celery |
| Data-at-rest secrets | `SECRETS_BACKEND` + backend creds | credentials, webhooks, SMTP/S3 channel secrets |
| Metrics scrape token | `METRICS_BEARER_TOKEN` | `/api/v1/metrics` |
| Readiness token | `READINESS_BEARER_TOKEN` | detailed readiness (optional) |
| PostgreSQL | `POSTGRES_PASSWORD` | api, worker, migrate |
| Bootstrap admin | `BOOTSTRAP_ADMIN_PASSWORD` or `_FILE` | first local admin |
| Keycloak client secret | Keycloak admin / realm export | confidential clients |
| Redis password | in `REDIS_URL` | Celery broker, cache, locks |
| SMTP | `SMTP_PASSWORD` | email notifications |
| S3 | `S3_SECRET_KEY` | scheduled report delivery |
| Vault Transit | `VAULT_ADDR`, `VAULT_TOKEN` / `_FILE` | `SECRETS_BACKEND=vault` |
| AWS KMS | `AWS_KMS_KEY_ID`, `AWS_KMS_REGION` | `SECRETS_BACKEND=aws_kms` |

---

## 2. SECRET_KEY and SECRETS_BACKEND

```powershell
# Generate (32 bytes hex)
openssl rand -hex 32
```

- Set the **same** `SECRET_KEY` on the `api` and `worker` services (JWT local auth, Celery signing).
- Encryption of credentials/webhooks uses a separate backend via `SECRETS_BACKEND`:
  - `fernet` — dev default (key derived from `SECRET_KEY`);
  - `vault` — HashiCorp Vault Transit (`VAULT_ADDR`, `VAULT_TOKEN` or `VAULT_TOKEN_FILE`);
  - `aws_kms` — BYO-KMS (`AWS_KMS_KEY_ID`, optionally `AWS_KMS_REGION`).
- In production with `APP_ENV=production`:
  - the dev-default `SECRET_KEY` is **rejected**;
  - `SECRETS_BACKEND=fernet` is **rejected**, except with an explicit `SECRETS_FERNET_ALLOWED_IN_PRODUCTION=true` (migration).
- Envelope prefixes when storing: `fernet:`, `vault:`, `awskms:` — decrypt also supports legacy Fernet without a prefix.
- KMS/Vault rotation: change the key in the backend → new records are encrypted with the new key; old ciphertext remains readable via the envelope prefix.

### Vault Transit (example)

```bash
vault secrets enable transit
vault write -f transit/keys/secaudit
```

```env
SECRETS_BACKEND=vault
VAULT_ADDR=https://vault.internal:8200
VAULT_TOKEN_FILE=/run/secrets/vault_token
VAULT_TRANSIT_KEY=secaudit
```

### AWS KMS (example)

```env
SECRETS_BACKEND=aws_kms
AWS_KMS_KEY_ID=arn:aws:kms:us-east-1:123456789012:key/abcd-efgh
AWS_KMS_REGION=us-east-1
```

---

## 3. METRICS_BEARER_TOKEN

```powershell
openssl rand -hex 24
```

- In production, without a token, the `/api/v1/metrics` endpoint returns **503**.
- Pass it via the `Authorization: Bearer <token>` header or `X-Observability-Token`.
- Store it in a secret manager; in Prometheus use `bearer_token` / `authorization` scrape config.

---

## 4. PostgreSQL passwords

- Dev default: `secaudit_dev` — **local development only**.
- Production: use a long random password and a dedicated DB user with least privilege.
- Do not expose `5432` externally unless necessary.

---

## 5. Bootstrap admin (local auth)

Opt-in, only when the `users` table is empty:

```env
LOCAL_AUTH_ENABLED=true
BOOTSTRAP_ADMIN_USERNAME=platform-admin
BOOTSTRAP_ADMIN_EMAIL=platform-admin@example.com
# One of the two:
BOOTSTRAP_ADMIN_PASSWORD=...        # dev/lab only
BOOTSTRAP_ADMIN_PASSWORD_FILE=/run/secrets/bootstrap_admin_password
```

Recommendations:

1. Prefer `_FILE` and Docker/K8s secrets.
2. Placeholder passwords are blocked (`dev`, `admin`, `password`, …).
3. After the first login, create permanent users in the UI and **remove** the bootstrap env.

---

## 6. Keycloak

- The dev realm is imported from `infra/keycloak/` — client secrets there are for **dev only**.
- Production: create clients in Keycloak Admin; export config **without** secrets into git.
- The confidential client secret belongs only in a secret store.
- Keep `KEYCLOAK_URL` (internal JWKS) and `KEYCLOAK_ISSUER` (public issuer) aligned.

---

## 7. Redis auth

Dev compose:

```env
REDIS_URL=redis://redis:6379/0
```

Production (example):

```env
REDIS_URL=rediss://:YOUR_PASSWORD@redis.internal:6379/0
CELERY_BROKER_URL=rediss://:YOUR_PASSWORD@redis.internal:6379/0
CELERY_RESULT_BACKEND=rediss://:YOUR_PASSWORD@redis.internal:6379/1
```

---

## 8. Password files (pattern)

`BOOTSTRAP_ADMIN_PASSWORD_FILE` is read as trimmed file text. The same pattern works with orchestrator secrets:

```yaml
# docker compose (example)
secrets:
  bootstrap_admin_password:
    file: ./secrets/bootstrap_admin_password.txt
services:
  api:
    secrets:
      - bootstrap_admin_password
    environment:
      BOOTSTRAP_ADMIN_PASSWORD_FILE: /run/secrets/bootstrap_admin_password
```

Add `secrets/` to `.gitignore`.

---

## 9. What NOT to commit

- `.env`, `.env.local`, `.env.production`
- `secrets/`, `*.pem`, `*.key`
- Keycloak realm JSON with client secrets (use placeholders + manual setup)
- `body.json`, coverage artifacts, `tmp-report-*.pdf`
- Celery beat schedule binary (`workers/celerybeat-schedule`)
- Bootstrap/password dumps

---

## 10. Checklist before commit/push

- [ ] `git status` — no `.env` or password files
- [ ] README/docs reference `.env.example`, not real values
- [ ] Production checklist: [production-guide.md](production-guide.md)
