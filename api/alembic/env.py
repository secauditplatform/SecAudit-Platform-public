import os
import sys
from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

# Repo root packages/ on path for secaudit_core (local dev + Docker).
_api_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
_repo_root = os.path.abspath(os.path.join(_api_root, ".."))
_packages = os.path.join(_repo_root, "packages")
if _packages not in sys.path:
    sys.path.insert(0, _packages)

from secaudit_core.models import Base  # noqa: E402
import secaudit_core.models  # noqa: F401, E402

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def _database_url() -> str:
    url = config.get_main_option("sqlalchemy.url")
    if url and not url.startswith("driver://"):
        return url

    try:
        from app.core.config import settings

        return settings.database_url_sync
    except Exception:
        user = os.environ.get("POSTGRES_USER", "secaudit")
        password = os.environ.get("POSTGRES_PASSWORD", "secaudit_dev")
        host = os.environ.get("POSTGRES_HOST", "localhost")
        port = os.environ.get("POSTGRES_PORT", "5432")
        db = os.environ.get("POSTGRES_DB", "secaudit")
        return f"postgresql://{user}:{password}@{host}:{port}/{db}"


def run_migrations_offline() -> None:
    url = _database_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    configuration = config.get_section(config.config_ini_section) or {}
    configuration["sqlalchemy.url"] = _database_url()
    connectable = engine_from_config(
        configuration,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
