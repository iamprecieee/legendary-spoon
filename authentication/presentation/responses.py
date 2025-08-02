from pydantic import BaseModel

from users.presentation.responses import UserResponse


class LoginResponse(UserResponse):
    """Response model for successful user login.

    Combines user details with authentication tokens.

    Attributes:
        access_token: The JWT access token.
        refresh_token: The JWT refresh token.
        token_type: The type of token (default: "bearer").
    """

    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class TokenResponse(BaseModel):
    """Response model for token retrieval (e.g., from OAuth2 password flow).

    Attributes:
        access_token: The JWT access token.
        token_type: The type of token (e.g., "bearer").
    """

    access_token: str
    token_type: str


class OAuthLoginResponse(BaseModel):
    """Response model for initiating an OAuth login, providing the authorization URL.

    Attributes:
        oauth_url: The URL to which the client should redirect for OAuth authentication.
    """

    oauth_url: str
