from pydantic import BaseModel


class UserCreateRequest(BaseModel):
    """Request model for new user registration.

    Attributes
    ----------
    email: str
        User's email address.
    password: str
        User's chosen password.
    """

    email: str
    password: str


class UserLoginRequest(UserCreateRequest):
    """Request model for user login.

    Inherit email and password fields from `UserCreateRequest`.
    """

    pass


class RefreshRequest(BaseModel):
    """Request model for refreshing an access token.

    Attributes
    ----------
    refresh_token: str
        Refresh token used to obtain a new access token.
    """

    refresh_token: str


class LogoutRequest(BaseModel):
    """Request model for user logout.

    Attributes
    ----------
    refresh_token: str
        Refresh token to be revoked during logout.
    """

    refresh_token: str


class UserOAuthLoginRequest(BaseModel):
    """Request model for initiating an OAuth login flow.

    This model is currently empty but can be extended if additional parameters
    are needed for OAuth login initiation.
    """

    pass
