from datetime import UTC, datetime, timedelta

from sqlmodel import Field, SQLModel

from config.base import get_settings

settings = get_settings()


class RefreshToken(SQLModel, table=True):
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
    id: int | None = Field(default=None, primary_key=True)
    token: str = Field(unique=True, nullable=False, index=True)
    blacklisted_at: datetime = Field(default_factory=lambda: datetime.now(tz=UTC))
    expires_at: datetime = Field(nullable=False)
