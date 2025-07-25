from abc import ABC, abstractmethod

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
