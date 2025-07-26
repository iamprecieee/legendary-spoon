from pydantic import BaseModel

from users.presentation.responses import UserResponse


class LoginResponse(UserResponse):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class OAuthLoginResponse(BaseModel):
    oauth_url: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str
