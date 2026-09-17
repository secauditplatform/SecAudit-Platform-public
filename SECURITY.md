# Security Policy

## Supported versions

Security fixes are applied on the latest published source on the default branch (`main` / `master`). Older snapshots are not patched separately unless a commercial support agreement says otherwise.

## Reporting a vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities.

Email: **secauditplatform@proton.me**

Include as much of the following as you can:

- Affected component (API, worker, frontend, Compose/Helm, docs)
- Version or commit hash
- Steps to reproduce, or a proof-of-concept
- Impact (auth bypass, secret exposure, RCE, data leak, etc.)
- Whether you plan a public disclosure date

We aim to acknowledge reports within **7 days** and to share a remediation or mitigation plan when we have one.

## Lab vs production

The root `docker-compose.yml` and `infra/keycloak/secaudit-realm.json` are **lab only** (weak default passwords, Keycloak `start-dev`, open redirect URIs). Do not expose them to the internet or reuse those credentials in production.

For production hardening, see [docs/production-guide.md](docs/production-guide.md) and [docs/secrets-howto.md](docs/secrets-howto.md).
