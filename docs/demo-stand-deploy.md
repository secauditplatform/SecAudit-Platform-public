# SecAudit — public demo stand

Locked-down deployment of [SecAudit-Platform](https://github.com/secauditplatform/SecAudit-Platform) on an external VPS.

Public example: [https://demo.secaudit.app](https://demo.secaudit.app)

| Item | Value |
|------|--------|
| Compose | `docker-compose.prod.yml` + `docker-compose.demo.yml` |
| Redis | Standalone (prod Compose default) |
| Observability | **Off** (do not use `--profile observability`) |
| Auth | Local only; SSO button visible but disabled |
| Execute APIs | Blocked (`DEMO_MODE=true`) |

## What is disabled

- Compliance job **run**, remediation **run**, AuditFlow / inventory **nmap** scans (UI buttons inactive; mutate APIs return 403)
- Playbook **run**, credential/host/profile mutations (API blocked)
- Notifications / scheduled reports
- Keycloak SSO (no IdP in the stack; SSO button visible but disabled)
- Console: enabled for demo, but **only `ping`** is allowed

Nav sections (Playbooks, AuditFlow, Console, Credentials, etc.) stay visible for product walkthrough.

## 1. Host prep (Ubuntu)

```bash
sudo apt update
sudo apt install -y ca-certificates curl git ufw fail2ban

# Docker (official)
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
  | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
  | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
```

Firewall (only SSH + HTTP/HTTPS):

```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow OpenSSH
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw --force enable
sudo ufw status verbose
```

fail2ban (sshd):

```bash
sudo systemctl enable --now fail2ban
sudo tee /etc/fail2ban/jail.local >/dev/null <<'EOF'
[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 5

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
backend = systemd
EOF
sudo systemctl restart fail2ban
sudo fail2ban-client status sshd
```

## 2. Code

Choose an install directory (example below uses `/opt/secaudit`):

```bash
export INSTALL_DIR=/opt/secaudit
sudo mkdir -p "$INSTALL_DIR"
sudo chown "$USER":"$USER" "$INSTALL_DIR"
cd "$INSTALL_DIR"
git clone https://github.com/secauditplatform/SecAudit-Platform.git .
```

Place profile packages under `./profiles` if you want a catalog in the UI (optional for a locked demo).

## 3. Secrets and bootstrap admin

```bash
cd "$INSTALL_DIR"
cp deploy/compose/.env.demo.example deploy/compose/.env
chmod 600 deploy/compose/.env

mkdir -p deploy/compose/secrets
# Write the demo admin password (one line, no trailing spaces). File mode 600.
# Example: printf '%s' 'YOUR_PASSWORD' > deploy/compose/secrets/bootstrap_admin_password.txt
chmod 600 deploy/compose/secrets/bootstrap_admin_password.txt

# Generate app secrets into .env:
#   openssl rand -hex 32   → SECRET_KEY / POSTGRES_PASSWORD / REDIS_PASSWORD / METRICS_BEARER_TOKEN
```

`BOOTSTRAP_ADMIN_USERNAME=admin` is allowed only because `DEMO_MODE=true`.

## 4. Start stack

```bash
cd "$INSTALL_DIR"
docker compose \
  -f deploy/compose/docker-compose.prod.yml \
  -f deploy/compose/docker-compose.demo.yml \
  --env-file deploy/compose/.env \
  up -d --build
```

Do **not** add `--profile observability`.

Health:

```bash
curl -sS http://127.0.0.1:8000/api/v1/health/live
curl -sS -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8080/
```

After first successful login, remove bootstrap secret from the running env if desired (user already exists in DB):

```bash
# optional: clear BOOTSTRAP_* from .env and recreate api without the secret
```

## 5. TLS (reverse proxy)

Place TLS materials outside the app tree (example: `/etc/ssl/secaudit/`). Do not commit certificates to git.

```bash
sudo mkdir -p /etc/ssl/secaudit
# copy fullchain.pem + privkey.pem (or your CA-issued pair) into /etc/ssl/secaudit/
sudo chmod 600 /etc/ssl/secaudit/privkey.pem
```

### Caddy example

Replace `DEMO_HOSTNAME` with your public hostname:

```bash
sudo apt install -y caddy
sudo tee /etc/caddy/Caddyfile >/dev/null <<'EOF'
DEMO_HOSTNAME {
        tls /etc/ssl/secaudit/fullchain.pem /etc/ssl/secaudit/privkey.pem
        encode gzip
        reverse_proxy 127.0.0.1:8080
}
EOF
sudo systemctl enable --now caddy
sudo systemctl reload caddy
```

If cert filenames differ, update the `tls` line accordingly.

### nginx alternative

```nginx
server {
    listen 443 ssl http2;
    server_name DEMO_HOSTNAME;
    ssl_certificate     /etc/ssl/secaudit/fullchain.pem;
    ssl_certificate_key /etc/ssl/secaudit/privkey.pem;
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
```

DNS: A/AAAA for `DEMO_HOSTNAME` → VPS public IP.

## 6. Smoke checks

- [ ] HTTPS login page loads
- [ ] SSO button visible and **disabled**
- [ ] Local login works with bootstrap admin
- [ ] Creating/running a job returns **403** (demo mode)
- [ ] AuditFlow / remediation / credentials create blocked
- [ ] `ufw status` shows only 22/80/443
- [ ] `fail2ban-client status sshd` active
- [ ] No Grafana/Prometheus/Tempo containers running

## Notes

- Lab root `docker-compose.yml` must **not** be used on a public VPS.
- Workers stay in the stack but cannot be driven into remote-exec via API while `DEMO_MODE=true`.
- For a richer UI demo, import sample profiles/reports offline before enabling demo mode, or seed DB from a backup.
