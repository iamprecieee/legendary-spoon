from fastapi import Depends
from sqlmodel import Session

from authentication.infrastructure.services import JWTTokenService, PasswordService
from config.base import Settings, get_settings
from config.database import get_db

from ..infrastructure.repositories import (
    BlacklistTokenRepository,
    RefreshTokenRepository,
)


async def get_refresh_token_repository(
    db: Session = Depends(get_db),
) -> RefreshTokenRepository:
    return RefreshTokenRepository(db)


async def get_blacklist_token_repository(
    db: Session = Depends(get_db),
) -> BlacklistTokenRepository:
    return BlacklistTokenRepository(db)


async def get_password_service(
    settings: Settings = Depends(get_settings),
) -> PasswordService:
    return PasswordService(settings)


async def get_jwt_token_service(
    settings: Settings = Depends(get_settings),
) -> JWTTokenService:
    return JWTTokenService(settings)
