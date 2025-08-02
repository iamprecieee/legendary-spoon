from abc import ABC, abstractmethod
from typing import Any, Dict

from ..domain.entities import User as DomainUser


class UserRepository(ABC):
    """Abstract base class for user data access operations.

    Defines the interface for interacting with user data, including creation,
    retrieval by various identifiers, and linking social accounts.
    """

    @abstractmethod
    async def create(self, user: DomainUser) -> DomainUser:
        """Creates a new user record.

        Args:
            user: The `DomainUser` entity to be created.

        Returns:
            The created `DomainUser` entity.
        """
        pass

    @abstractmethod
    async def get_by_email(self, email: str) -> DomainUser:
        """Retrieves a user by their email address.

        Args:
            email: The email address of the user to retrieve.

        Returns:
            The `DomainUser` entity matching the email.
        """
        pass

    @abstractmethod
    async def get_by_id(self, user_id: int) -> DomainUser:
        """Retrieves a user by their unique ID.

        Args:
            user_id: The ID of the user to retrieve.

        Returns:
            The `DomainUser` entity matching the ID.
        """
        pass

    @abstractmethod
    async def get_by_social_id(self, social_id: str) -> DomainUser | None:
        """Retrieves a user by their social media ID.

        Args:
            social_id: The social media ID of the user to retrieve.

        Returns:
            The `DomainUser` entity if found, otherwise None.
        """
        pass

    @abstractmethod
    async def link_social_account(
        self, user_email: str, social_data: Dict[str, Any]
    ) -> DomainUser:
        """Links a social account to an existing user.

        Args:
            user_email: The email of the existing user to link.
            social_data: A dictionary containing social account information (e.g., social ID).

        Returns:
            The updated `DomainUser` entity with the linked social account.
        """
        pass
