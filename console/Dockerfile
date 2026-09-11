FROM python:3.12-slim

WORKDIR /app

# Network diagnostics only — this image is the console sandbox blast-radius boundary.
RUN apt-get update && apt-get install -y --no-install-recommends \
    bash iputils-ping traceroute dnsutils whois nmap \
    net-tools iproute2 tcpdump \
    && ln -sf /usr/sbin/traceroute /usr/bin/tracert \
    && groupadd --system secaudit \
    && useradd --system --gid secaudit --home-dir /nonexistent --shell /usr/sbin/nologin secaudit \
    && install -d -o root -g root -m 0555 /var/empty/secaudit-console \
    && rm -rf /var/lib/apt/lists/*

COPY console/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY packages/secaudit_core /packages/secaudit_core
RUN pip install --no-cache-dir -e /packages/secaudit_core

# Reuse API console session + auth (no Postgres/Celery runtime needed).
COPY api/app /app/app

USER secaudit:secaudit

EXPOSE 8001

CMD ["uvicorn", "app.console_main:app", "--host", "0.0.0.0", "--port", "8001"]
