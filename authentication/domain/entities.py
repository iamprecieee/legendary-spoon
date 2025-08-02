from datetime import datetime

from pydantic import dataclasses


@dataclasses.dataclass
class RefreshToken:
    """Represents a refresh token used for obtaining new access tokens.

    Attributes:
        token: The unique string value of the refresh token.
        user_id: The ID of the user to whom this refresh token belongs.
        is_revoked: A boolean indicating if the token has been revoked (default: False).
        expires_at: The datetime at which the token expires (optional).
        created_at: The datetime when the token was created (optional).
        id: The unique identifier for the refresh token entry (optional).
    """

    token: str
    user_id: int
    is_revoked: bool = False
    expires_at: datetime | None = None
    created_at: datetime | None = None
    id: int | None = None


@dataclasses.dataclass
class BlacklistedToken:
    """Represents an access token that has been explicitly blacklisted.

    Blacklisted tokens are no longer valid for authentication, even if their
    natural expiry time has not yet passed.

    Attributes:
        token: The string value of the blacklisted access token.
        expires_at: The original expiry datetime of the blacklisted token.
        blacklisted_at: The datetime when the token was added to the blacklist (optional).
        id: The unique identifier for the blacklisted token entry (optional).
    """

    token: str
    expires_at: datetime
    blacklisted_at: datetime | None = None
    id: int | None = None


@dataclasses.dataclass
class TokenPair:
    """Represents a pair of access and refresh tokens.

    Attributes:
        access_token: The JWT access token.
        refresh_token: The JWT refresh token.
        token_type: The type of token (default: "bearer").
        expires_in: The lifespan of the access token in minutes (default: 30).
    """

    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int = 30  # minutes
