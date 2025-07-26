from abc import ABC, abstractmethod
from typing import Any, Dict

from ..domain.entities import User as DomainUser


class UserRepository(ABC):
    @abstractmethod
    def create(self, user: DomainUser) -> DomainUser:
        pass

    @abstractmethod
    def get_by_email(self, email: str) -> DomainUser:
        pass

    @abstractmethod
    def get_by_id(self, user_id: int) -> DomainUser:
        pass

    @abstractmethod
    def get_by_social_id(self, social_id: str) -> DomainUser | None:
        pass

    @abstractmethod
    def link_social_account(
        self, user_email: str, social_data: Dict[str, Any]
    ) -> DomainUser:
        pass
