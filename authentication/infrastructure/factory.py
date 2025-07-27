from fastapi import Depends
from sqlmodel import Session

from authentication.infrastructure.services import (
    GoogleOAuthService,
    JWTTokenService,
    PasswordService,
)
from config.base import Settings, get_settings
from config.database import get_database_session

from ..infrastructure.repositories import (
    BlacklistTokenRepository,
    RefreshTokenRepository,
)


async def get_refresh_token_repository(
    session: Session = Depends(get_database_session),
) -> RefreshTokenRepository:
    return RefreshTokenRepository(session)


async def get_blacklist_token_repository(
    session: Session = Depends(get_database_session),
) -> BlacklistTokenRepository:
    return BlacklistTokenRepository(session)


async def get_password_service(
    settings: Settings = Depends(get_settings),
) -> PasswordService:
    return PasswordService(settings)


async def get_jwt_token_service(
    settings: Settings = Depends(get_settings),
) -> JWTTokenService:
    return JWTTokenService(settings)


async def get_google_oauth_service(
    settings: Settings = Depends(get_settings),
) -> GoogleOAuthService:
    return GoogleOAuthService(settings)
