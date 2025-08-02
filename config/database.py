from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlmodel import SQLModel

from alembic import command
from alembic.config import Config

from .base import Settings, get_settings


def get_database_url(settings: Settings, is_async=False) -> str:
    """Constructs the database URL based on environment settings.

    Args:
        settings: The application settings object.
        is_async: A boolean indicating whether to return an asynchronous URL (default: False).

    Returns:
        A string representing the database connection URL.

    Raises:
        ValueError: If the environment is not "development" (as per current implementation).
    """
    if not settings.environment.lower() == "development":
        raise ValueError(f'Unsupported environment: "{settings.environment}"')

    if is_async:
        return f"sqlite+aiosqlite:///{settings.base_dir}/db.sqlite3"
    else:
        return f"sqlite:///{settings.base_dir}/db.sqlite3"


async def get_database_engine():
    """Provides an asynchronous SQLAlchemy database engine.

    The engine is configured based on the application's database URL.

    Returns:
        An asynchronous SQLAlchemy engine instance.
    """
    settings = get_settings()
    database_url = get_database_url(settings, is_async=True)

    return create_async_engine(database_url)


async def get_database_session():
    """Provides an asynchronous SQLAlchemy session.

    This function is designed to be used as a FastAPI dependency,
    providing a database session that is automatically closed after use.

    Yields:
        An asynchronous SQLAlchemy session instance.
    """
    engine = await get_database_engine()
    async with AsyncSession(bind=engine) as session:
        try:
            yield session
        finally:
            await session.close()


async def create_tables():
    """Asynchronously creates all database tables defined in SQLModel metadata.

    This function is typically called during application startup to ensure
    that the database schema is up-to-date with the defined models.
    """
    engine = await get_database_engine()

    async with engine.begin() as connection:
        await connection.run_sync(SQLModel.metadata.create_all)


async def run_migrations():
    """Runs Alembic database migrations to upgrade the database schema to the latest version.

    Configures Alembic with the appropriate database URL and executes the 'upgrade head' command.
    """
    settings = get_settings()
    database_url = get_database_url(settings, is_async=True)

    alembic_cfg = Config("alembic.ini")
    alembic_cfg.set_main_option("sqlalchemy.url", str(database_url))

    command.upgrade(alembic_cfg, "head")
