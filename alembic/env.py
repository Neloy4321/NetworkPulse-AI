"""NetworkPulse schema migration environment.

Connection is supplied by networkpulse.migrations so credentials need not be
written into files. Direct alembic CLI use falls back to the ini database URL.
"""
from logging.config import fileConfig

from alembic import context
from sqlalchemy import create_engine

from networkpulse.storage import Base

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def run_migrations_online():
    connection = config.attributes.get("connection")
    if connection is not None:
        context.configure(connection=connection, target_metadata=target_metadata,
                          render_as_batch=connection.dialect.name == "sqlite")
        with context.begin_transaction():
            context.run_migrations()
        return
    engine = create_engine(config.get_main_option("sqlalchemy.url"), future=True)
    try:
        with engine.connect() as conn:
            context.configure(connection=conn, target_metadata=target_metadata,
                              render_as_batch=conn.dialect.name == "sqlite")
            with context.begin_transaction():
                context.run_migrations()
    finally:
        engine.dispose()


def run_migrations_offline():
    context.configure(url=config.get_main_option("sqlalchemy.url"),
                      target_metadata=target_metadata, literal_binds=True)
    with context.begin_transaction():
        context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
