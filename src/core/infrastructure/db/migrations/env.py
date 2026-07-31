import asyncio
import contextlib
from logging.config import fileConfig

from alembic import context
from sqlalchemy import create_engine, pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import async_engine_from_config

from src.core.infrastructure.config import settings
from src.core.infrastructure.db.models import Base

config = context.config

current_url = config.get_main_option("sqlalchemy.url")
if (not current_url or current_url == "postgresql+asyncpg://govsec:govsec@localhost:5432/govsec") and settings.GOVSEC_DB_URL:
    config.set_main_option("sqlalchemy.url", settings.GOVSEC_DB_URL)

if config.config_file_name is not None:
    with contextlib.suppress(Exception):
        fileConfig(config.config_file_name, disable_existing_loggers=False)


target_metadata = Base.metadata


def run_migrations_offline() -> None:
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        version_num_dim=255,
    )
    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: Connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        version_num_dim=255,
    )
    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    connectable = async_engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)
    await connectable.dispose()


def run_migrations_online() -> None:
    url = config.get_main_option("sqlalchemy.url") or ""
    if "sqlite" in url and "aiosqlite" not in url:
        connectable = create_engine(url, poolclass=pool.NullPool)
        with connectable.connect() as connection:
            do_run_migrations(connection)
        connectable.dispose()
    else:
        asyncio.run(run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
