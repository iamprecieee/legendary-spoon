from pydantic import BaseModel

from users.presentation.responses import UserResponse


class LoginResponse(UserResponse):
    """Response model for successful user login.

    Combine user details with authentication tokens.

    Attributes
    ----------
    access_token: str
        JWT access token.
    refresh_token: str
        JWT refresh token.
    token_type: str, default="bearer"
        Type of token.
    """

    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class TokenResponse(BaseModel):
    """Response model for token retrieval (e.g., from OAuth2 password flow).

    Attributes
    ----------
    access_token: str
        JWT access token.
    token_type: str
        Type of token.
    """

    access_token: str
    token_type: str


class OAuthLoginResponse(BaseModel):
    """Response model for initiating an OAuth login, providing the authorization URL.

    Attributes
    ----------
    oauth_url: str
        URL to which the client should redirect for OAuth authentication.
    """

    oauth_url: str
