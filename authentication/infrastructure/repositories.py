from datetime import datetime, timezone

from fastapi import HTTPException, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select

from cache.infrastructure.decorators import cache

from ..application.ports import (
    BlacklistTokenRepository as DomainBlacklistTokenRepository,
)
from ..application.ports import RefreshTokenRepository as DomainRefreshTokenRepository
from ..domain.entities import BlacklistedToken as BlacklistToken
from ..domain.entities import BlacklistedToken as DomainBlacklistedToken
from ..domain.entities import RefreshToken as DomainRefreshToken
from ..infrastructure.models import BlacklistedToken, RefreshToken


class RefreshTokenRepository(DomainRefreshTokenRepository):
    """Concrete implementation of `RefreshTokenRepository` for database-based refresh token management."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def create(self, refresh_token: DomainRefreshToken) -> DomainRefreshToken:
        """Create a new refresh token record in the database.

        Parameters
        ----------
        refresh_token: DomainRefreshToken
            Domain `DomainRefreshToken` entity to be created.

        Returns
        -------
        DomainRefreshToken
            Created `DomainRefreshToken` entity, hydrated with database-assigned values.

        Raises
        ------
        IntegrityError
            If there is a database integrity violation during creation (e.g., duplicate token).
        Exception
            For other unexpected database errors.
        """
        refresh_token = self._to_pydantic_model(refresh_token)

        self._session.add(refresh_token)
        try:
            await self._session.commit()
            await self._session.refresh(refresh_token)
        except IntegrityError as e:
            await self._session.rollback()
            e.orig = "Failed to create refresh token"
            raise e

        except Exception as e:
            await self._session.rollback()
            raise e

        return self._to_domain_model(refresh_token)

    @cache(timeout_seconds=300, key_prefix="auth:token")
    async def get_by_token(self, token: str) -> DomainRefreshToken:
        """Retrieve a refresh token by its string value from the database.

        Parameters
        ----------
        token: str
            String value of the refresh token to retrieve.

        Returns
        -------
        DomainRefreshToken
            `DomainRefreshToken` entity if found and valid.

        Raises
        ------
        HTTPException
            If the token is not found, is revoked, or has expired.
        """
        refresh_token_data = await self._session.execute(
            select(RefreshToken).where(
                RefreshToken.token == token,
                RefreshToken.is_revoked == False,
                RefreshToken.expires_at > datetime.now(),
            )
        )
        pydantic_refresh_token = refresh_token_data.first()

        if not pydantic_refresh_token:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Non-existent or blacklisted refresh token",
            )

        pydantic_refresh_token = pydantic_refresh_token[0]
        return self._to_domain_model(pydantic_refresh_token)

    async def revoke_token(self, token: str, user_id: int) -> None:
        """Revoke a refresh token by marking it as revoked in the database.

        Parameters
        ----------
        token: str
            String value of the refresh token to revoke.

        Raises
        ------
        HTTPException
            If the token is not found.
        Exception
            For other unexpected database errors.
        """
        refresh_token_data = await self._session.execute(
            select(RefreshToken).where(
                RefreshToken.token == token,
                RefreshToken.user_id == user_id,
                RefreshToken.is_revoked == False,
                RefreshToken.expires_at > datetime.now(),
            )
        )
        pydantic_refresh_token = refresh_token_data.scalars().first()

        if not pydantic_refresh_token:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Refresh token not found or does not belong to user",
            )

        pydantic_refresh_token.is_revoked = True
        self._session.add(pydantic_refresh_token)

        try:
            await self._session.commit()
            await self._session.refresh(pydantic_refresh_token)

        except Exception as e:
            await self._session.rollback()
            raise e

    def _to_pydantic_model(
        self, domain_refresh_token: DomainRefreshToken
    ) -> RefreshToken:
        """Convert a domain `DomainRefreshToken` entity to a Pydantic `RefreshToken` model.

        Parameters
        ----------
        domain_refresh_token: DomainRefreshToken
            Domain entity to convert.

        Returns
        -------
        RefreshToken
            Pydantic `RefreshToken` model instance.
        """
        domain_data = domain_refresh_token.__dict__.copy()

        domain_data.pop("id", None)
        domain_data.pop("created_at", None)
        domain_data.pop("expires_at", None)

        return RefreshToken(**domain_data)

    def _to_domain_model(
        self, pydantic_refresh_token: RefreshToken
    ) -> DomainRefreshToken:
        """Convert a Pydantic `RefreshToken` model to a domain `DomainRefreshToken` entity.

        Parameters
        ----------
        pydantic_refresh_token: RefreshToken
            Pydantic model to convert.

        Returns
        -------
        DomainRefreshToken
            Domain `DomainRefreshToken` entity instance.
        """
        return DomainRefreshToken(**pydantic_refresh_token.model_dump())


class BlacklistTokenRepository(DomainBlacklistTokenRepository):
    """Concrete implementation of `BlacklistTokenRepository` for managing blacklisted tokens in the database."""

    def __init__(self, db: AsyncSession) -> None:
        """Initializes the BlacklistTokenRepository.

        Args:
            db: The asynchronous SQLAlchemy session for database operations.
        """
        self._session = db

    async def create(self, token: BlacklistToken) -> None:
        """Add an access token to the blacklist.

        Parameters
        ----------
        token: BlacklistToken
            Domain `BlacklistToken` entity to be blacklisted.

        Raises
        ------
        IntegrityError
            If there is a database integrity violation during creation (e.g., duplicate token).
        Exception
            For other unexpected database errors.
        """
        pydantic_token = self._to_pydantic_model(token)

        self._session.add(pydantic_token)
        try:
            await self._session.commit()
        except IntegrityError as e:
            await self._session.rollback()
            e.orig = "Failed to blacklist token"
            raise e

        except Exception as e:
            await self._session.rollback()

            raise e

    @cache(timeout_seconds=300, key_prefix="auth:token_blacklisted")
    async def is_token_blacklisted(self, token: str, raise_error: bool = False) -> bool:
        """Check if a given token is present in the blacklist and is still active.

        Parameters
        ----------
        token: str
            Access token string to check.
        raise_error: bool, default=False
            If `True`, raises an `HTTPException` if the token is blacklisted.

        Returns
        -------
        bool
            `True` if the token is blacklisted and not expired, `False` otherwise.

        Raises
        ------
        HTTPException
            If `raise_error` is `True` and the token is blacklisted.
        """
        token_data = await self._session.execute(
            select(BlacklistedToken).where(
                BlacklistedToken.token == token,
                BlacklistedToken.expires_at > datetime.now(timezone.utc),
            )
        )
        blacklisted = token_data.first()
        is_blacklisted = blacklisted is not None

        if is_blacklisted and raise_error:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication token is blacklisted",
            )

        return is_blacklisted

    def _to_pydantic_model(
        self, domain_blacklisted_token: DomainBlacklistedToken
    ) -> BlacklistedToken:
        """Convert a domain `DomainBlacklistedToken` entity to a Pydantic `BlacklistedToken` model.

        Parameters
        ----------
        domain_blacklisted_token: DomainBlacklistedToken
            Domain entity to convert.

        Returns
        -------
        BlacklistedToken
            Pydantic `BlacklistedToken` model instance.
        """
        domain_data = domain_blacklisted_token.__dict__.copy()

        domain_data.pop("id", None)
        domain_data.pop("blacklisted_at", None)

        return BlacklistedToken(**domain_data)

    def _to_domain_model(
        self, pydantic_blacklisted_token: BlacklistedToken
    ) -> DomainBlacklistedToken:
        """Convert a Pydantic `BlacklistedToken` model to a domain `DomainBlacklistedToken` entity.

        Parameters
        ----------
        pydantic_blacklisted_token: BlacklistedToken
            Pydantic model to convert.

        Returns
        -------
        DomainBlacklistedToken
            Domain `DomainBlacklistedToken` entity instance.
        """
        return DomainBlacklistedToken(**pydantic_blacklisted_token.model_dump())
