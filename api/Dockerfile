FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libpq-dev fonts-dejavu-core chromium openssh-client \
    bash iputils-ping traceroute dnsutils whois nmap \
    net-tools iproute2 tcpdump \
    && ln -sf /usr/sbin/traceroute /usr/bin/tracert \
    && groupadd --system --gid 1000 secaudit \
    && useradd --system --uid 1000 --gid secaudit --home-dir /nonexistent --shell /usr/sbin/nologin secaudit \
    && install -d -o root -g root -m 0555 /var/empty/secaudit-console \
    && install -d -o secaudit -g secaudit -m 0750 /data/profiles \
    && rm -rf /var/lib/apt/lists/*

COPY api/requirements.txt api/requirements-dev.txt ./
RUN pip install --no-cache-dir -r requirements.txt -r requirements-dev.txt

COPY packages/secaudit_core /packages/secaudit_core
RUN pip install --no-cache-dir -e /packages/secaudit_core

COPY api/ansible-collections.yml .
RUN mkdir -p /usr/share/ansible/collections \
    && ansible-galaxy collection install -r ansible-collections.yml -p /usr/share/ansible/collections \
    && chmod -R a+rX /usr/share/ansible

COPY api/ .

USER secaudit:secaudit

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]