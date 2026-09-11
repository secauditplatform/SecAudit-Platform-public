import logging
import os
from contextlib import asynccontextmanager, contextmanager
from pathlib import Path

from alembic import command
from alembic.config import Config
from fastapi import FastAPI
from sqlalchemy import create_engine, inspect, text
from fastapi.middleware.cors import CORSMiddleware

from app.api.v1.router import api_router
from app.core.config import settings
from app.core.database import async_session, engine as async_engine
from app.middleware.demo_mode import DemoModeGuardMiddleware
from app.middleware.observability import observability_middleware
from app import models  # noqa: F401 — register ORM tables
from app.services.bootstrap_admin import maybe_bootstrap_admin
from app.services.profiles import CategoryService, ProfileService
from secaudit_core.security import (
    validate_production_runtime_config,
    validate_production_secret_key,
    validate_production_secrets_backend,
)
from secaudit_core.tracing import (
    configure_tracing,
    instrument_asyncpg,
    instrument_fastapi,
    instrument_http_clients,
    instrument_sqlalchemy,
)

logger = logging.getLogger(__name__)

# Stable lock key so concurrent API replicas serialize DDL.
_MIGRATION_ADVISORY_LOCK_KEY = 872_014_028

_LEGACY_BASELINE_TABLES = frozenset(
    {
        "jobs",
        "job_runs",
        "hosts",
        "check_results",
        "remediation_jobs",
        "remediation_runs",
        "remediation_results",
        "task_outbox",
    }
)


def _validate_legacy_baseline(tables: set[str]) -> None:
    missing = sorted(_LEGACY_BASELINE_TABLES - tables)
    if missing:
        raise RuntimeError(
            "Refusing legacy Alembic stamp: database is missing required tables "
            f"{missing}. Restore from backup or create a fresh database and run "
            "`alembic upgrade head`."
        )


@contextmanager
def _migration_advisory_lock(sync_url: str):
    """Hold a PostgreSQL session-level advisory lock for the duration of upgrades."""
    engine = create_engine(sync_url)
    conn = engine.connect()
    try:
        dialect = conn.dialect.name
        if dialect == "postgresql":
            conn.execute(
                text("SELECT pg_advisory_lock(:key)"),
                {"key": _MIGRATION_ADVISORY_LOCK_KEY},
            )
            conn.commit()
        try:
            yield
        finally:
            if dialect == "postgresql":
                conn.execute(
                    text("SELECT pg_advisory_unlock(:key)"),
                    {"key": _MIGRATION_ADVISORY_LOCK_KEY},
                )
                conn.commit()
    finally:
        conn.close()
        engine.dispose()


def _run_alembic_upgrade() -> None:
    """Apply Alembic migrations (sync). Skipped when SKIP_MIGRATIONS=1 (tests).

    Concurrent API replicas serialize via PostgreSQL advisory lock. Legacy DBs
    without ``alembic_version`` are no longer silently stamped to head unless
    ``ALLOW_LEGACY_ALEMBIC_STAMP=1`` and a validated baseline schema are present.
    """
    if os.environ.get("SKIP_MIGRATIONS") == "1":
        return

    alembic_ini = Path(__file__).resolve().parents[1] / "alembic.ini"
    cfg = Config(str(alembic_ini))
    cfg.set_main_option("sqlalchemy.url", settings.database_url_sync)

    with _migration_advisory_lock(settings.database_url_sync):
        engine = create_engine(settings.database_url_sync)
        try:
            tables = set(inspect(engine).get_table_names())
        finally:
            engine.dispose()

        if "alembic_version" not in tables and "jobs" in tables:
            allow_stamp = os.environ.get("ALLOW_LEGACY_ALEMBIC_STAMP") == "1"
            if not allow_stamp:
                raise RuntimeError(
                    "Database has application tables but no alembic_version row. "
                    "Refusing automatic stamp-to-head (fail closed). "
                    "Either run a validated baseline stamp with "
                    "ALLOW_LEGACY_ALEMBIC_STAMP=1 after confirming schema matches "
                    "head, or restore alembic_version / recreate the database."
                )
            _validate_legacy_baseline(tables)
            logger.warning(
                "ALLOW_LEGACY_ALEMBIC_STAMP=1: stamping legacy database to head "
                "after baseline table validation"
            )
            command.stamp(cfg, "head")
        else:
            command.upgrade(cfg, "head")


# Survives uvicorn --reload within one container (/tmp is tmpfs in Compose).
_STARTUP_MARKER = Path("/tmp/.secaudit_api_startup_done")


async def _run_startup_bootstrap() -> None:
    async with async_session() as session:
        await CategoryService().seed_defaults(session)
        await ProfileService().migrate_legacy_packages(session)
        await ProfileService().reconcile_profile_categories(session)
        seeded = await ProfileService().seed_bundled_profiles(session)
        if seeded:
            logger.info("Auto-seeded %s bundled profile profile(s)", seeded)
        await maybe_bootstrap_admin(session)
        await session.commit()


@asynccontextmanager
async def lifespan(app: FastAPI):
    validate_production_secret_key(settings.secret_key, settings.app_env)
    validate_production_runtime_config(
        app_env=settings.app_env,
        auth_enabled=settings.auth_enabled,
        api_debug=settings.api_debug,
    )
    validate_production_secrets_backend(
        app_env=settings.app_env,
        secrets_backend=settings.secrets_backend,
        secrets_fernet_allowed_in_production=settings.secrets_fernet_allowed_in_production,
        vault_addr=settings.vault_addr,
        vault_token=settings.vault_token,
        vault_token_file=settings.vault_token_file,
        aws_kms_key_id=settings.aws_kms_key_id,
    )
    settings.validate_bootstrap_admin_security()

    # Schema: `migrate` service in Compose, or alembic here when SKIP_MIGRATIONS is unset.
    # Data seed (categories/profiles/admin) runs once per container — not on every uvicorn reload.
    skip_migrations = os.environ.get("SKIP_MIGRATIONS") == "1"
    if not skip_migrations:
        _run_alembic_upgrade()

    if not _STARTUP_MARKER.exists():
        await _run_startup_bootstrap()
        _STARTUP_MARKER.touch()
        logger.info("API startup bootstrap completed")
    else:
        logger.debug("Skipping API startup bootstrap (already initialized in this container)")

    yield


_tracing_enabled = configure_tracing("secaudit-api", settings=settings)

app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    debug=settings.api_debug,
    lifespan=lifespan,
)

if _tracing_enabled:
    instrument_fastapi(app, settings=settings)
    instrument_sqlalchemy(async_engine, settings=settings)
    instrument_asyncpg(settings=settings)
    instrument_http_clients(settings=settings)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(DemoModeGuardMiddleware, enabled=settings.demo_mode)


@app.middleware("http")
async def _observability(request, call_next):
    return await observability_middleware(request, call_next)

app.include_router(api_router, prefix="/api/v1")


@app.get("/")
async def root() -> dict:
    return {
        "app": settings.app_name,
        "version": settings.app_version,
        "docs": "/docs",
        "api": "/api/v1",
    }
