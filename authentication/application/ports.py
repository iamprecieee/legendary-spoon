from abc import ABC, abstractmethod
from typing import Any, Dict

from users.domain.entities import User as DomainUser

from ..domain.entities import BlacklistedToken as DomainBlacklistedToken
from ..domain.entities import RefreshToken as DomainRefreshToken


class PasswordServiceInterface(ABC):
    @abstractmethod
    def hash_password(self, password: str) -> str:
        pass

    @abstractmethod
    def check_password(self, raw_password: str, hashed_password: str) -> bool:
        pass


class JWTTokenServiceInterface(ABC):
    @abstractmethod
    def create_access_token(self, user: DomainUser) -> str:
        pass

    @abstractmethod
    def create_refresh_token(self, user: DomainUser) -> str:
        pass

    @abstractmethod
    def decode_jwt_token(self, token: str) -> Dict[str, Any]:
        pass

    @abstractmethod
    def decode_access_token(self, token: str) -> DomainUser | None:
        pass

    @abstractmethod
    def decode_refresh_token(self, token: str) -> dict | None:
        pass


class RefreshTokenRepository(ABC):
    @abstractmethod
    def create(self, refresh_token: DomainRefreshToken) -> DomainRefreshToken:
        pass

    @abstractmethod
    def get_by_token(self, token: str, raise_error: bool = False) -> DomainRefreshToken:
        pass

    @abstractmethod
    def revoke_token(self, token: str) -> None:
        pass


class BlacklistTokenRepository(ABC):
    @abstractmethod
    def create(self, token: DomainBlacklistedToken) -> None:
        pass

    @abstractmethod
    def is_token_blacklisted(self, token: str, raise_error: bool = False) -> bool:
        pass


class OAuthServiceInterface(ABC):
    @abstractmethod
    def get_authorization_url(self, state: str) -> str:
        pass

    @abstractmethod
    async def exchange_auth_code(self, auth_code: str) -> Dict[str, Any]:
        pass

    @abstractmethod
    async def fetch_user_info(self, access_token: str) -> Dict[str, Any]:
        pass
