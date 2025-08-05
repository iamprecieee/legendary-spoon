from fastapi import Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from config.base import Settings, get_settings
from config.database import get_database_session
from users.application.ports import UserRepository
from users.domain.entities import User as DomainUser
from users.infrastructure.factory import get_user_repository

from ..application.rules import CurrentUserRule
from ..infrastructure.custom_oauth2_schemes import OAuth2PasswordBearerWithEmail
from ..infrastructure.repositories import (
    BlacklistTokenRepository,
    RefreshTokenRepository,
)
from ..infrastructure.services import (
    GoogleOAuthService,
    JWTTokenService,
    PasswordService,
)

oauth2_scheme = OAuth2PasswordBearerWithEmail(tokenUrl="/auth/token")


async def get_password_service(
    settings: Settings = Depends(get_settings),
) -> PasswordService:
    """Provide a `PasswordService` instance.

    Parameters
    ----------
    settings: Settings
        Application settings, injected as a dependency.

    Returns
    -------
    PasswordService
        Instance of `PasswordService`.
    """
    return PasswordService(settings)


async def get_jwt_token_service(
    settings: Settings = Depends(get_settings),
) -> JWTTokenService:
    """Provide a `JWTTokenService` instance.

    Parameters
    ----------
    settings: Settings
        Application settings, injected as a dependency.

    Returns
    -------
    JWTTokenService
        Instance of `JWTTokenService`.
    """
    return JWTTokenService(settings)


async def get_refresh_token_repository(
    session: AsyncSession = Depends(get_database_session),
) -> RefreshTokenRepository:
    """Provide a `RefreshTokenRepository` instance.

    Parameters
    ----------
    session: AsyncSession
        Asynchronous SQLAlchemy database session, injected as a dependency.

    Returns
    -------
    RefreshTokenRepository
        Instance of `RefreshTokenRepository`.
    """
    return RefreshTokenRepository(session)


async def get_blacklist_token_repository(
    session: AsyncSession = Depends(get_database_session),
) -> BlacklistTokenRepository:
    """Provide a `BlacklistTokenRepository` instance.

    Parameters
    ----------
    session: AsyncSession
        Asynchronous SQLAlchemy database session, injected as a dependency.

    Returns
    -------
    BlacklistTokenRepository
        Instance of `BlacklistTokenRepository`.
    """
    return BlacklistTokenRepository(session)


async def get_current_user(
    token: str = Depends(oauth2_scheme),
    blacklisted_token_repository: BlacklistTokenRepository = Depends(
        get_blacklist_token_repository
    ),
    user_repository: UserRepository = Depends(get_user_repository),
    token_service: JWTTokenService = Depends(get_jwt_token_service),
) -> DomainUser:
    """Provide the current authenticated user based on the access token.

    Checks if the provided token is blacklisted
    and then uses the `CurrentUserRule` to retrieve the user.

    Parameters
    ----------
    token: str
        Access token obtained from the request header.
    blacklisted_token_repository: BlacklistTokenRepository
        Repository for checking blacklisted tokens.
    user_repository: UserRepository
        Repository for user data access.
    token_service: JWTTokenService
        Service for JWT token operations.

    Returns
    -------
    DomainUser
        `DomainUser` entity of the currently authenticated user.

    Raises
    ------
    HTTPException
        If the token is invalid, blacklisted, or the user cannot be found.
    """
    try:
        await blacklisted_token_repository.is_token_blacklisted(token, raise_error=True)
        current_user_rule = CurrentUserRule(
            token=token, token_service=token_service, user_repository=user_repository
        )
        current_user = await current_user_rule.execute()
        return current_user

    except HTTPException:
        raise

    except Exception as e:
        raise e


async def get_google_oauth_service(
    settings: Settings = Depends(get_settings),
) -> GoogleOAuthService:
    """Provide a `GoogleOAuthService` instance.

    Parameters
    ----------
    settings: Settings
        Application settings, injected as a dependency.

    Returns
    -------
    GoogleOAuthService
        Instance of `GoogleOAuthService`.
    """
    return GoogleOAuthService(settings)
