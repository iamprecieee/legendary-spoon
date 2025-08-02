from datetime import UTC, datetime, timedelta

from sqlmodel import Field, SQLModel

from config.base import get_settings

settings = get_settings()


class RefreshToken(SQLModel, table=True):
    """SQLModel for storing refresh tokens.

    Attributes:
        id: Primary key, auto-incrementing integer.
        token: The unique refresh token string, indexed for quick lookups.
        user_id: The ID of the associated user, a foreign key to the user table.
        expires_at: The datetime when the token expires. Defaults to `refresh_token_expiry`
                    minutes from creation.
        is_revoked: Boolean indicating if the token has been revoked (default: False).
        created_at: The datetime when the token was created.
    """

    id: int | None = Field(default=None, primary_key=True)
    token: str = Field(unique=True, nullable=False, index=True)
    user_id: int = Field(foreign_key="user.id", nullable=False)
    expires_at: datetime = Field(
        default_factory=lambda: datetime.now(tz=UTC)
        + timedelta(days=settings.refresh_token_expiry)
    )
    is_revoked: bool = Field(default=False)
    created_at: datetime = Field(default_factory=lambda: datetime.now(tz=UTC))


class BlacklistedToken(SQLModel, table=True):
    """SQLModel for storing blacklisted access tokens.

    Attributes:
        id: Primary key, auto-incrementing integer.
        token: The unique blacklisted token string, indexed for quick lookups.
        blacklisted_at: The datetime when the token was blacklisted.
        expires_at: The original expiry datetime of the token.
    """

    id: int | None = Field(default=None, primary_key=True)
    token: str = Field(unique=True, nullable=False, index=True)
    blacklisted_at: datetime = Field(default_factory=lambda: datetime.now(tz=UTC))
    expires_at: datetime = Field(nullable=False)
