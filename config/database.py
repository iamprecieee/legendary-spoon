from sqlmodel import Session, SQLModel, create_engine

from alembic import command
from alembic.config import Config

from .base import Settings, get_settings


def get_database_url(settings: Settings) -> str:
    if settings.environment.lower() == "development":
        return f"sqlite:///{settings.base_dir}/db.sqlite3"

    raise ValueError(f'Unsupported environment: "{settings.envronment}"')


def get_database_engine():
    settings = get_settings()
    database_url = get_database_url(settings)

    return create_engine(database_url)


def get_database_session():
    engine = get_database_engine()
    with Session(bind=engine) as session:
        try:
            yield session
        finally:
            session.close()


def create_tables():
    engine = get_database_engine()
    SQLModel.metadata.create_all(engine)


def run_migrations():
    """Runs Alembic migrations to upgrade the database schema to the latest version."""

    alembic_cfg = Config("alembic.ini")
    command.upgrade(alembic_cfg, "head")
