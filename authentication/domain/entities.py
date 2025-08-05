from datetime import datetime

from pydantic import dataclasses


@dataclasses.dataclass
class RefreshToken:
    """Core domain entity representing a refresh token for obtaining new access tokens.

    Attributes
    ----------
        token: str
            Unique string value of refresh token.
        user_id: int
            ID of user to whom this refresh token belongs.
        is_revoked: bool, default=False
            Boolean indicating if token has been revoked.
        expires_at: datetime | None, optional
            Datetime at which token expires.
        created_at: datetime | None, optional
            Datetime when token was created.
        id: int | None, optional
            Unique identifier for refresh token entry.
    """

    token: str
    user_id: int
    is_revoked: bool = False
    expires_at: datetime | None = None
    created_at: datetime | None = None
    id: int | None = None


@dataclasses.dataclass
class BlacklistedToken:
    """Core domain entity representing an explicitly blacklisted access token.

    Attributes
    ----------
    token: str
        String value of blacklisted access token.
    expires_at: datetime
        Original expiry datetime of blacklisted token.
    blacklisted_at: datetime | None, optional
        Datetime when token was added to blacklist.
    id: int | None, optional
        Unique identifier for blacklisted token entry.
    """

    token: str
    expires_at: datetime
    blacklisted_at: datetime | None = None
    id: int | None = None


@dataclasses.dataclass
class TokenPair:
    """Core domain entity representing a pair of access and refresh tokens.

    Attributes
    ----------
    access_token: str
        JWT access token.
    refresh_token: str
        JWT refresh token.
    token_type: str, default="bearer"
        Type of token.
    expires_in: int, default=30
        Lifespan of access token in minutes.
    """

    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int = 30
