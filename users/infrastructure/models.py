from datetime import UTC, datetime

from sqlmodel import Field, SQLModel

from config.base import get_settings

settings = get_settings()


class User(SQLModel, table=True):
    """SQLModel table representation for the User entity.

    Attributes
    ----------
    id: int | None, optional
        Primary key, auto-incrementing integer.
    email: str
        Unique email address of the user, indexed for quick lookups.
    password: str
        Hashed password of the user. Can be null for users authenticated via OAuth.
    social_id: str | None, optional
        Unique identifier from a social login provider (e.g., Google ID). Nullable.
    is_active: bool, default=True
        Boolean indicating if the user account is active.
    created_at: datetime
        Datetime when the user record was created.
    """

    id: int | None = Field(default=None, primary_key=True)
    email: str = Field(unique=True, nullable=False, index=True)
    password: str = Field(nullable=False)
    social_id: str | None = Field(default=None, nullable=True)
    is_active: bool = Field(default=True)
    created_at: datetime = Field(default_factory=lambda: datetime.now(tz=UTC))
