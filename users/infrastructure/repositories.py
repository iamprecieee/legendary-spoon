from typing import Any, Dict

from fastapi import HTTPException, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select

from core.infrastructure.cache.decorators import cache

from ..application.ports import UserRepository as DomainUserRepository
from ..domain.entities import User as DomainUser
from ..infrastructure.models import User


class UserRepository(DomainUserRepository):
    """Concrete implementation of `UserRepository` for managing user data in the database.

    This repository handles CRUD operations for users, including linking social accounts,
    and mapping between domain entities and SQLModel ORM objects.
    """

    def __init__(self, session: AsyncSession) -> None:
        """Initializes the UserRepository.

        Args:
            session: The asynchronous SQLAlchemy session for database operations.
        """
        self._session = session

    async def create(self, user: DomainUser) -> DomainUser:
        """Creates a new user record in the database.

        Args:
            user: The `DomainUser` entity to be created.

        Returns:
            The created `DomainUser` entity, hydrated with database-assigned values.

        Raises:
            IntegrityError: If a user with the same email already exists or other integrity violations occur.
            Exception: For other unexpected database errors.
        """
        user = self._to_pydantic_model(user)
        self._session.add(user)
        try:
            await self._session.commit()
            await self._session.refresh(user)
        except IntegrityError as e:
            await self._session.rollback()

            e.orig = (
                "User with this email already exists"
                if "user.email" in str(e.orig)
                else e.orig
            )
            raise e
        except Exception as e:
            await self._session.rollback()

            raise e

        return self._to_domain_model(user)

    @cache(timeout_seconds=300, key_prefix="user:email")
    async def get_by_email(self, email: str) -> DomainUser:
        """Retrieves a user by their email address from the database.

        Args:
            email: The email address of the user to retrieve.

        Returns:
            The `DomainUser` entity matching the email.

        Raises:
            HTTPException: If no user is found with the provided email.
        """
        user_data = await self._session.execute(select(User).where(User.email == email))
        pydantic_user = user_data.first()
        if not pydantic_user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
            )
        pydantic_user = pydantic_user[0]
        return self._to_domain_model(pydantic_user)

    @cache(timeout_seconds=300, key_prefix="user:id")
    async def get_by_id(self, user_id: int) -> DomainUser:
        """Retrieves a user by their unique ID from the database.

        Args:
            user_id: The ID of the user to retrieve.

        Returns:
            The `DomainUser` entity matching the ID.

        Raises:
            HTTPException: If no user is found with the provided ID.
        """
        user_data = await self._session.execute(select(User).where(User.id == user_id))
        pydantic_user = user_data.first()
        if not pydantic_user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
            )
        pydantic_user = pydantic_user[0]
        return self._to_domain_model(pydantic_user)

    @cache(timeout_seconds=300, key_prefix="user:social_id")
    async def get_by_social_id(self, social_id: str) -> DomainUser | None:
        """Retrieves a user by their social media ID from the database.

        Args:
            social_id: The social media ID of the user to retrieve.

        Returns:
            The `DomainUser` entity if found, otherwise None.
        """
        user_data = await self._session.execute(
            select(User).where(User.social_id == social_id)
        )
        pydantic_user = user_data.first()
        if not pydantic_user:
            return None
        pydantic_user = pydantic_user[0]
        return self._to_domain_model(pydantic_user)

    async def link_social_account(
        self, user_email: str, social_data: Dict[str, Any]
    ) -> DomainUser:
        """Links a social account to an existing user identified by email.

        Updates the existing user's `social_id` with the provided social data.

        Args:
            user_email: The email of the existing user to link.
            social_data: A dictionary containing social account information,
                         expected to have an 'id' key for the social ID.

        Returns:
            The updated `DomainUser` entity with the linked social account.

        Raises:
            HTTPException: If no user is found with the provided email.
            IntegrityError: If there's an integrity violation during the update.
            Exception: For other unexpected database errors.
        """
        user_data = await self._session.execute(
            select(User).where(User.email == user_email)
        )
        pydantic_user = user_data.first()
        if not pydantic_user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
            )
        pydantic_user = pydantic_user[0]
        pydantic_user.social_id = social_data.get("id")

        self._session.add(pydantic_user)
        try:
            await self._session.commit()
            await self._session.refresh(pydantic_user)
        except IntegrityError:
            await self._session.rollback()
            return False
        except Exception as e:
            await self._session.rollback()

            raise e

    def _to_pydantic_model(self, domain_user: DomainUser) -> User:
        """Converts a domain `DomainUser` entity to a Pydantic `User` model.

        Args:
            domain_user: The domain entity to convert.

        Returns:
            A Pydantic `User` model instance.
        """
        domain_data = domain_user.__dict__.copy()

        domain_data.pop("id", None)
        domain_data.pop("created_at", None)

        return User(**domain_data)

    def _to_domain_model(self, pydantic_user: User) -> DomainUser:
        """Converts a Pydantic `User` model to a domain `DomainUser` entity.

        Args:
            pydantic_user: The Pydantic model to convert.

        Returns:
            A domain `DomainUser` entity instance.
        """
        return DomainUser(**pydantic_user.model_dump())
