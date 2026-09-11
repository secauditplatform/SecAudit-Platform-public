FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libpq-dev openssh-client sshpass iputils-ping nmap fonts-dejavu-core chromium \
    && groupadd --system --gid 1000 secaudit \
    && useradd --system --uid 1000 --gid secaudit --home-dir /nonexistent --shell /usr/sbin/nologin secaudit \
    && install -d -o secaudit -g secaudit -m 0750 /data/profiles \
    && rm -rf /var/lib/apt/lists/*

COPY workers/requirements.txt workers/requirements-dev.txt ./
RUN pip install --no-cache-dir -r requirements.txt -r requirements-dev.txt

COPY packages/secaudit_core /packages/secaudit_core
RUN pip install --no-cache-dir -e /packages/secaudit_core

COPY workers/ansible-collections.yml .
RUN mkdir -p /usr/share/ansible/collections \
    && ansible-galaxy collection install -r ansible-collections.yml -p /usr/share/ansible/collections \
    && chmod -R a+rX /usr/share/ansible

COPY workers/ .

USER secaudit:secaudit

CMD ["celery", "-A", "app.celery_app", "worker", "--loglevel=info"]
