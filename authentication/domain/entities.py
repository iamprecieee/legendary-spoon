from datetime import datetime

from pydantic import dataclasses


@dataclasses.dataclass
class RefreshToken:
    token: str
    user_id: int
    is_revoked: bool = False
    expires_at: datetime | None = None
    created_at: datetime | None = None
    id: int | None = None


@dataclasses.dataclass
class BlacklistedToken:
    token: str
    expires_at: datetime
    blacklisted_at: datetime | None = None
    id: int | None = None


@dataclasses.dataclass
class TokenPair:
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int = 30  # minutes
