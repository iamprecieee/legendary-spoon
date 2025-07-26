from datetime import datetime, timezone

from fastapi import HTTPException, status
from loguru import logger
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, select

from ..application.ports import (
    BlacklistTokenRepository as DomainBlacklistTokenRepository,
)
from ..application.ports import RefreshTokenRepository as DomainRefreshTokenRepository
from ..domain.entities import BlacklistedToken as BlacklistToken
from ..domain.entities import BlacklistedToken as DomainBlacklistedToken
from ..domain.entities import RefreshToken as DomainRefreshToken
from ..infrastructure.models import BlacklistedToken, RefreshToken


class RefreshTokenRepository(DomainRefreshTokenRepository):
    def __init__(self, db: Session) -> None:
        self._db = db

    def create(self, refresh_token: DomainRefreshToken) -> DomainRefreshToken:
        refresh_token = self._to_pydantic_model(refresh_token)

        self._db.add(refresh_token)
        try:
            self._db.commit()
            self._db.refresh(refresh_token)
        except IntegrityError as e:
            self._db.rollback()
            e.orig = "Failed to create refresh token"
            raise e
        except Exception as e:
            self._db.rollback()
            logger.error(
                f"💥 Unhandled exception occurred while creating refresh_token: {e}"
            )

        return self._to_domain_model(refresh_token)

    def get_by_token(self, token: str) -> DomainRefreshToken:
        pydantic_refresh_token = self._db.exec(
            select(RefreshToken).where(
                RefreshToken.token == token,
                not RefreshToken.is_revoked,
                RefreshToken.expires_at > datetime.now(),
            )
        ).first()
        if not pydantic_refresh_token:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Invalid refresh token"
            )

        return self._to_domain_model(pydantic_refresh_token)

    def revoke_token(self, token: str) -> None:
        pydantic_refresh_token = self._db.exec(
            select(RefreshToken).where(RefreshToken.token == token)
        ).first()
        if pydantic_refresh_token and not pydantic_refresh_token.is_revoked:
            pydantic_refresh_token.is_revoked = True
            self._db.add(pydantic_refresh_token)
            self._db.commit()
            self._db.refresh(pydantic_refresh_token)

    def _to_pydantic_model(
        self, domain_refresh_token: DomainRefreshToken
    ) -> RefreshToken:
        domain_data = domain_refresh_token.__dict__.copy()

        # Remove fields managed by the DB or not needed for creation
        domain_data.pop("id", None)
        domain_data.pop("created_at", None)
        domain_data.pop("expires_at", None)

        return RefreshToken(**domain_data)

    def _to_domain_model(
        self, pydantic_refresh_token: RefreshToken
    ) -> DomainRefreshToken:
        return DomainRefreshToken(**pydantic_refresh_token.model_dump())


class BlacklistTokenRepository(DomainBlacklistTokenRepository):
    def __init__(self, db: Session) -> None:
        self._db = db

    def create(self, token: BlacklistToken) -> None:
        pydantic_token = self._to_pydantic_model(token)

        self._db.add(pydantic_token)
        try:
            self._db.commit()
        except IntegrityError as e:
            self._db.rollback()
            e.orig = "Failed to blacklist token"
            raise e
        except Exception as e:
            self._db.rollback()
            logger.error(
                f"💥 Unhandled exception occurred while blacklisting token: {e}"
            )

    def is_token_blacklisted(self, token: str, raise_error: bool = False) -> bool:
        blacklisted = self._db.exec(
            select(BlacklistedToken).where(
                BlacklistedToken.token == token,
                BlacklistedToken.expires_at > datetime.now(timezone.utc),
            )
        ).first()

        is_blacklisted = blacklisted is not None

        if is_blacklisted and raise_error:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication token",
            )

        return is_blacklisted

    def _to_pydantic_model(
        self, domain_blacklisted_token: DomainBlacklistedToken
    ) -> BlacklistedToken:
        domain_data = domain_blacklisted_token.__dict__.copy()

        # Remove fields managed by the DB or not needed for creation
        domain_data.pop("id", None)
        domain_data.pop("blacklisted_at", None)

        return BlacklistedToken(**domain_data)

    def _to_domain_model(
        self, pydantic_blacklisted_token: BlacklistedToken
    ) -> DomainBlacklistedToken:
        return DomainBlacklistedToken(**pydantic_blacklisted_token.model_dump())
