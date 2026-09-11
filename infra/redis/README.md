# Redis HA (Sentinel)

SecAudit uses **Redis Sentinel by default** in Docker Compose: `redis-master`, `redis-replica`, and three sentinels (`secaudit-master`, quorum 2/3).

| Mode | Compose command | Connection |
|------|-----------------|------------|
| **Sentinel HA** (default) | `docker compose up -d` | `REDIS_SENTINEL_HOSTS=redis-sentinel-1:26379,...` |
| **Standalone** (optional, CI / experiments) | `docker compose --profile standalone up -d redis` | `REDIS_URL=redis://redis:6379/0` |

## Sentinel stack

- `redis-master` — primary Redis 7 (AOF)
- `redis-replica` — hot standby
- `redis-sentinel-{1,2,3}` — quorum 2/3, master name `secaudit-master`
  - `sentinel resolve-hostnames yes` — required for Docker service names on Alpine
  - config is copied to `/tmp/sentinel.conf` at start (Sentinel rewrites resolved hostnames)

Application services resolve the current master through Sentinel. Celery broker/backend use the same master name with logical DBs `0` (broker + app state) and `1` (results).

## Environment variables

```env
REDIS_SENTINEL_HOSTS=redis-sentinel-1:26379,redis-sentinel-2:26379,redis-sentinel-3:26379
REDIS_SENTINEL_MASTER_NAME=secaudit-master
# REDIS_SENTINEL_PASSWORD=        # if sentinels require auth
# REDIS_PASSWORD=                 # if Redis master requires auth
REDIS_URL=redis://secaudit-master/0  # logical URL: DB index only (host ignored in Sentinel mode)
CELERY_BROKER_URL=redis://secaudit-master/0
CELERY_RESULT_BACKEND=redis://secaudit-master/1
```

When `REDIS_SENTINEL_HOSTS` is set, all platform Redis clients (sync + asyncio) and Celery use Sentinel automatically.

> **Important:** All services that touch Redis (api, worker, beat, migrate) must share the same Sentinel settings. After changing Redis mode, recreate them together:
> `docker compose up -d --force-recreate migrate api worker beat`

## Production notes

- Use managed Redis with Sentinel or an external HA endpoint when possible.
- Enable `REDIS_PASSWORD` and TLS (`REDIS_SSL=true`) in production.
- Keep broker DB `/0` and result backend DB `/1` separate.
