from abc import ABC, abstractmethod
from typing import Any, Dict

from ..domain.entities import User as DomainUser


class UserRepository(ABC):
    """Abstract base class for user data management.

    Defines the interface for interacting with user data, including creation,
    retrieval by various identifiers, and linking social accounts.
    """

    @abstractmethod
    async def create(self, user: DomainUser) -> DomainUser:
        """Create a new user record.

        Parameters
        ----------
        user: DomainUser
            User entity to be created.

        Returns
        -------
        DomainUser
            Created User entity.
        """
        pass

    @abstractmethod
    async def get_by_email(self, email: str) -> DomainUser:
        """Retrieve a user by their email address.

        Parameters
        ----------
        email: str
            Email address of user to retrieve.

        Returns
        -------
        DomainUser
            `DomainUser` entity matching email.
        """
        pass

    @abstractmethod
    async def get_by_id(self, user_id: int) -> DomainUser:
        """Retrieve a user by their unique ID.

        Parameters
        ----------
        user_id: int
            ID of user to retrieve.

        Returns
        -------
        DomainUser
            `DomainUser` entity matching ID.
        """
        pass

    @abstractmethod
    async def get_by_social_id(self, social_id: str) -> DomainUser | None:
        """Retrieve a user by their social media ID.

        Parameters
        ----------
        social_id: str
            Social oauth ID of user to retrieve.

        Returns
        -------
        DomainUser | None
            `DomainUser` entity if found, otherwise None.
        """
        pass

    @abstractmethod
    async def link_social_account(
        self, user_email: str, social_data: Dict[str, Any]
    ) -> DomainUser:
        """Link a social account to an existing user.

        Parameters
        ----------
        user_email: str
            Email of existing user to link.
        social_data: Dict[str, Any]
            Dictionary containing social account information (e.g., social ID).

        Returns
        -------
        DomainUser
            Updated `DomainUser` entity with linked social account.
        """
        pass
