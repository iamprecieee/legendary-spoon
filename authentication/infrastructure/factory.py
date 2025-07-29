from typing import Any

from fastapi import Depends
from sqlmodel import Session

from authentication.infrastructure.services import (
    GoogleOAuthService,
    JWTTokenService,
    PasswordService,
)
from config.base import Settings, get_settings
from config.database import get_database_session
from core.infrastructure.factory import get_data_sanitizer

from ..infrastructure.repositories import (
    BlacklistTokenRepository,
    RefreshTokenRepository,
)


async def get_refresh_token_repository(
    session: Session = Depends(get_database_session),
    sanitizer: Any = Depends(get_data_sanitizer),
) -> RefreshTokenRepository:
    return RefreshTokenRepository(session, sanitizer)


async def get_blacklist_token_repository(
    session: Session = Depends(get_database_session),
    sanitizer: Any = Depends(get_data_sanitizer),
) -> BlacklistTokenRepository:
    return BlacklistTokenRepository(session, sanitizer)


async def get_password_service(
    settings: Settings = Depends(get_settings),
) -> PasswordService:
    return PasswordService(settings)


async def get_jwt_token_service(
    settings: Settings = Depends(get_settings),
    sanitizer: Any = Depends(get_data_sanitizer),
) -> JWTTokenService:
    return JWTTokenService(settings, sanitizer)


async def get_google_oauth_service(
    settings: Settings = Depends(get_settings),
    sanitizer: Any = Depends(get_data_sanitizer),
) -> GoogleOAuthService:
    return GoogleOAuthService(settings, sanitizer)
