from pydantic import BaseModel


class UserCreateRequest(BaseModel):
    email: str
    password: str


class UserLoginRequest(UserCreateRequest):
    pass


class RefreshRequest(BaseModel):
    refresh_token: str


class LogoutRequest(BaseModel):
    refresh_token: str
