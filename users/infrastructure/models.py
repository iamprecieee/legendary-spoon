from datetime import UTC, datetime

from sqlmodel import Field, SQLModel

from config.base import get_settings

settings = get_settings()


class User(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    email: str = Field(unique=True, nullable=False, index=True)
    password: str = Field(default="", nullable=True)  # Optional for OAuth users
    social_id: str | None = Field(default=None, nullable=True)
    is_active: bool = Field(default=True)
    created_at: datetime = Field(default_factory=lambda: datetime.now(tz=UTC))
