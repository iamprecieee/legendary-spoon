from fastapi import Depends, HTTPException, status
from loguru import logger
from sqlmodel import Session

from authentication.application.rules import CurrentUserRule
from authentication.infrastructure.custom_oauth2_schemes import (
    OAuth2PasswordBearerWithEmail,
)
from authentication.infrastructure.factory import (
    get_blacklist_token_repository,
    get_jwt_token_service,
)
from authentication.infrastructure.repositories import BlacklistTokenRepository
from authentication.infrastructure.services import JWTTokenService
from config.database import get_db

from ..domain.entities import User as DomainUser
from .repositories import UserRepository

oauth2_scheme = OAuth2PasswordBearerWithEmail(tokenUrl="/auth/token")


async def get_user_repository(db: Session = Depends(get_db)) -> UserRepository:
    return UserRepository(db)


async def get_current_user(
    token: str = Depends(oauth2_scheme),
    blacklisted_token_repository: BlacklistTokenRepository = Depends(
        get_blacklist_token_repository
    ),
    user_repository: UserRepository = Depends(get_user_repository),
    token_service: JWTTokenService = Depends(get_jwt_token_service),
) -> DomainUser:
    try:
        # Check if the token is blacklisted (raises if so)
        blacklisted_token_repository.is_token_blacklisted(token, raise_error=True)
        current_user_rule = CurrentUserRule(
            token=token, token_service=token_service, user_repository=user_repository
        )

        current_user = current_user_rule.execute()
        return current_user

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"💥 Error retrieving current user: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
        ) from e
