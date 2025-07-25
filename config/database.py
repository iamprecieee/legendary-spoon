from sqlmodel import Session, SQLModel, create_engine

from alembic import command
from alembic.config import Config

from .base import Settings, get_settings


def get_db_url(settings: Settings) -> str:
    """
    Returns the database URL based on the current environment.
    Only 'development' environment is supported (SQLite) currently.
    """

    if settings.environment.lower() == "development":
        return f"sqlite:///{settings.base_dir}/db.sqlite3"

    raise ValueError(f'Unsupported environment: "{settings.envronment}"')


def get_engine():
    """Creates and returns a SQLModel engine using the current settings."""

    settings = get_settings()
    db_url = get_db_url(settings)
    return create_engine(db_url)


def get_db():
    """
    Dependency generator that yields a database session.
    Closes the session after use.
    """

    engine = get_engine()
    with Session(bind=engine) as session:
        try:
            yield session
        finally:
            session.close()


def run_migrations():
    """Runs Alembic migrations to upgrade the database schema to the latest version."""

    alembic_cfg = Config("alembic.ini")
    command.upgrade(alembic_cfg, "head")


def create_tables():
    """
    Creates all tables in the database based on SQLModel metadata.
    Used as a fallback if migrations fail.
    """

    engine = get_engine()
    SQLModel.metadata.create_all(engine)
