from typing import Any, Dict

from fastapi import HTTPException, status
from loguru import logger
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, select

from ..application.ports import UserRepository as DomainUserRepository
from ..domain.entities import User as DomainUser
from ..infrastructure.models import User


class UserRepository(DomainUserRepository):
    def __init__(self, session: Session, sanitizer: Any) -> None:
        self._session = session
        self.sanitizer = sanitizer

    def create(self, user: DomainUser) -> DomainUser:
        user = self._to_pydantic_model(user)

        self._session.add(user)
        try:
            self._session.commit()
            self._session.refresh(user)
        except IntegrityError as e:
            self._session.rollback()

            # Provide a clearer error message if the email is duplicated
            e.orig = (
                "User with this email already exists"
                if "user.email" in str(e.orig)
                else e.orig
            )
            raise e
        except Exception as e:
            self._session.rollback()
            if hasattr(e, "statement") and hasattr(e, "params"):
                safe_sql, safe_params = self.sanitizer.sanitize_sql_for_logging(
                    e.statement, e.params
                )
                logger.error(
                    f"📝 Unhandled exception occurred while creating user: {type(e).__name__} - SQL: {safe_sql}, Params: {safe_params}"
                )
            else:
                logger.error(
                    f"📝 Unhandled exception occurred while creating user: {type(e).__name__}: {self.sanitizer.sanitize_exception_for_logging(str(e))}"
                )

            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Internal server error",
            ) from e

        return self._to_domain_model(user)

    def get_by_email(self, email: str) -> DomainUser:
        pydantic_user = self._session.exec(
            select(User).where(User.email == email)
        ).first()
        if not pydantic_user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
            )

        return self._to_domain_model(pydantic_user)

    def get_by_id(self, user_id: int) -> DomainUser:
        pydantic_user = self._session.exec(
            select(User).where(User.id == user_id)
        ).first()
        if not pydantic_user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
            )

        return self._to_domain_model(pydantic_user)

    def get_by_social_id(self, social_id: str) -> DomainUser | None:
        pydantic_user = self._session.exec(
            select(User).where(User.social_id == social_id)
        ).first()
        if not pydantic_user:
            return None

        return self._to_domain_model(pydantic_user)

    def link_social_account(
        self, user_email: str, social_data: Dict[str, Any]
    ) -> DomainUser:
        pydantic_user = self._session.exec(
            select(User).where(User.email == user_email)
        ).first()
        if not pydantic_user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
            )

        pydantic_user.social_id = social_data.get("id")

        self._session.add(pydantic_user)
        try:
            self._session.commit()
            self._session.refresh(pydantic_user)
        except IntegrityError:
            self._session.rollback()
            return False
        except Exception as e:
            self._session.rollback()
            if hasattr(e, "statement") and hasattr(e, "params"):
                safe_sql, safe_params = self.sanitizer.sanitize_sql_for_logging(
                    e.statement, e.params
                )
                logger.error(
                    f"⛓️‍💥 Unhandled exception occurred while linking social account: {type(e).__name__} - SQL: {safe_sql}, Params: {safe_params}"
                )
            else:
                logger.error(
                    f"⛓️‍💥 Unhandled exception occurred while linking social account: {self.sanitizer.sanitize_exception_for_logging(e)}"
                )

            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Internal server error",
            ) from e

    def _to_pydantic_model(self, domain_user: DomainUser) -> User:
        domain_data = domain_user.__dict__.copy()

        # Remove fields managed by the database
        domain_data.pop("id", None)
        domain_data.pop("created_at", None)

        return User(**domain_data)

    def _to_domain_model(self, pydantic_user: User) -> DomainUser:
        return DomainUser(**pydantic_user.model_dump())
