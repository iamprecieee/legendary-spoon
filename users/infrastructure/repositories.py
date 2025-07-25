from fastapi import HTTPException, status
from loguru import logger
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, select

from ..application.ports import UserRepository as DomainUserRepository
from ..domain.entities import User as DomainUser
from ..infrastructure.models import User


class UserRepository(DomainUserRepository):
    def __init__(self, db: Session) -> None:
        self._db = db

    def create(self, user: DomainUser) -> DomainUser:
        user = self._to_pydantic_model(user)

        self._db.add(user)
        try:
            self._db.commit()
            self._db.refresh(user)
        except IntegrityError as e:
            self._db.rollback()

            # Provide a clearer error message if the email is duplicated
            e.orig = (
                "User with this email already exists"
                if "user.email" in str(e.orig)
                else e.orig
            )
            raise e
        except Exception as e:
            logger.exception(f"Unhandled exception occurred while creating user: {e}")

        return self._to_domain_model(user)

    def get_by_email(self, email: str) -> DomainUser:
        pydantic_user = self._db.exec(select(User).where(User.email == email)).first()
        if not pydantic_user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
            )

        return self._to_domain_model(pydantic_user)

    def get_by_id(self, user_id: int) -> DomainUser:
        pydantic_user = self._db.exec(select(User).where(User.id == user_id)).first()
        if not pydantic_user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
            )
        return self._to_domain_model(pydantic_user)

    def _to_pydantic_model(self, domain_user: DomainUser) -> User:
        domain_data = domain_user.__dict__.copy()

        # Remove fields managed by the database
        domain_data.pop("id", None)
        domain_data.pop("created_at", None)

        return User(**domain_data)

    def _to_domain_model(self, pydantic_user: User) -> DomainUser:
        return DomainUser(**pydantic_user.model_dump())
