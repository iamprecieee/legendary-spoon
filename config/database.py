from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, create_async_engine
from sqlmodel import SQLModel

from alembic import command
from alembic.config import Config

from .base import Settings, get_settings

_engine: AsyncEngine | None = None


def get_database_url(settings: Settings, is_async=False) -> str:
    """Construct the database URL based on environment settings.

    Parameters
    ----------
    settings: Settings
        Application settings object.
    is_async: bool, default=False
        Boolean indicating whether to return an asynchronous URL.

    Returns
    -------
    str
        String representing the database connection URL.

    Raises
    ------
    ValueError
        If environment is not "development" (as per current implementation).
    """
    if not settings.environment.lower() == "development":
        raise ValueError(f'Unsupported environment: "{settings.environment}"')

    if is_async:
        return f"sqlite+aiosqlite:///{settings.base_dir}/db.sqlite3"
    else:
        return f"sqlite:///{settings.base_dir}/db.sqlite3"


async def get_database_engine():
    """Provide a singleton asynchronous SQLAlchemy database engine.

    Returns
    -------
    _engine
        Asynchronous SQLAlchemy engine instance.
    """
    global _engine

    if _engine is None:
        settings = get_settings()
        database_url = get_database_url(settings, is_async=True)
        _engine = create_async_engine(database_url, echo=False)

    return _engine


async def close_database_engine():
    """Dispose of existing database engine."""
    global _engine

    if _engine:
        await _engine.dispose()
        _engine = None


async def get_database_session():
    """Provide an asynchronous SQLAlchemy session.

    Yields
    ------
    session
        Asynchronous SQLAlchemy session instance.
    """
    engine = await get_database_engine()
    async with AsyncSession(bind=engine) as session:
        try:
            yield session
        finally:
            await session.close()


async def create_tables():
    """Asynchronously create all database tables defined in SQLModel metadata."""
    engine = await get_database_engine()
    async with engine.begin() as connection:
        await connection.run_sync(SQLModel.metadata.create_all)


async def run_migrations():
    """Apply all pending database migrations.

    Executes unapplied migrations in chronological order to bring database schema
    up to date with current model definitions.

    Raises
    ------
    AlembicError
        If migration conflicts exist or database connection fails.
    """
    settings = get_settings()
    database_url = get_database_url(settings, is_async=True)

    alembic_cfg = Config("alembic.ini")
    alembic_cfg.set_main_option("sqlalchemy.url", str(database_url))
    command.upgrade(alembic_cfg, "head")
