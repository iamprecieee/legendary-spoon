from abc import ABC, abstractmethod
from typing import Any, Dict

from users.domain.entities import User as DomainUser

from ..domain.entities import BlacklistedToken as DomainBlacklistedToken
from ..domain.entities import RefreshToken as DomainRefreshToken


class PasswordServiceInterface(ABC):
    """Abstract base class for password-related services.

    Defines the interface for hashing and checking passwords,
    ensuring that concrete implementations adhere to these methods.
    """

    @abstractmethod
    async def hash_password(self, password: str) -> str:
        """Hashes a raw password.

        Args:
            password: The plain-text password to hash.

        Returns:
            The hashed password string.
        """
        pass

    @abstractmethod
    async def check_password(self, raw_password: str, hashed_password: str) -> bool:
        """Checks if a raw password matches a hashed password.

        Args:
            raw_password: The plain-text password to check.
            hashed_password: The hashed password to compare against.

        Returns:
            True if the passwords match, False otherwise.
        """
        pass


class JWTTokenServiceInterface(ABC):
    """Abstract base class for JSON Web Token (JWT) related services.

    Defines the interface for creating and decoding JWT access and refresh tokens.
    """

    @abstractmethod
    async def create_access_token(self, user: DomainUser) -> str:
        """Creates a new JWT access token for a given user.

        Args:
            user: The domain user entity for whom the token is created.

        Returns:
            The encoded JWT access token string.
        """
        pass

    @abstractmethod
    async def create_refresh_token(self, user: DomainUser) -> str:
        """Creates a new JWT refresh token for a given user.

        Args:
            user: The domain user entity for whom the token is created.

        Returns:
            The encoded JWT refresh token string.
        """
        pass

    @abstractmethod
    async def decode_jwt_token(self, token: str) -> Dict[str, Any]:
        """Decodes a given JWT token without specific validation.

        Args:
            token: The JWT token string to decode.

        Returns:
            A dictionary containing the decoded token payload.
        """
        pass

    @abstractmethod
    async def decode_access_token(self, token: str) -> DomainUser | None:
        """Decodes and validates a JWT access token.

        Args:
            token: The JWT access token string to decode.

        Returns:
            The `DomainUser` entity if the token is valid, otherwise None.
        """
        pass

    @abstractmethod
    async def decode_refresh_token(self, token: str) -> dict | None:
        """Decodes and validates a JWT refresh token.

        Args:
            token: The JWT refresh token string to decode.

        Returns:
            A dictionary containing the decoded token payload if valid, otherwise None.
        """
        pass


class RefreshTokenRepository(ABC):
    """Abstract base class for managing refresh tokens in the repository.

    Defines the interface for creating, retrieving, and revoking refresh tokens.
    """

    @abstractmethod
    async def create(self, refresh_token: DomainRefreshToken) -> DomainRefreshToken:
        """Creates a new refresh token in the repository.

        Args:
            refresh_token: The `DomainRefreshToken` entity to create.

        Returns:
            The created `DomainRefreshToken` entity.
        """
        pass

    @abstractmethod
    async def get_by_token(
        self, token: str, raise_error: bool = False
    ) -> DomainRefreshToken:
        """Retrieves a refresh token by its string value.

        Args:
            token: The refresh token string.
            raise_error: If True, raises an error if the token is not found.

        Returns:
            The `DomainRefreshToken` entity.
        """
        pass

    @abstractmethod
    async def revoke_token(self, token: str) -> None:
        """Revokes a refresh token, making it unusable.

        Args:
            token: The refresh token string to revoke.
        """
        pass


class BlacklistTokenRepository(ABC):
    """Abstract base class for managing blacklisted tokens in the repository.

    Defines the interface for blacklisting tokens and checking if a token is blacklisted.
    """

    @abstractmethod
    async def create(self, token: DomainBlacklistedToken) -> None:
        """Adds a token to the blacklist.

        Args:
            token: The `DomainBlacklistedToken` entity to blacklist.
        """
        pass

    @abstractmethod
    async def is_token_blacklisted(self, token: str, raise_error: bool = False) -> bool:
        """Checks if a token is present in the blacklist.

        Args:
            token: The token string to check.
            raise_error: If True, raises an error if the token is found in the blacklist.

        Returns:
            True if the token is blacklisted, False otherwise.
        """
        pass


class OAuthServiceInterface(ABC):
    """Abstract base class for OAuth-related services.

    Defines the interface for obtaining authorization URLs,
    exchanging authorization codes for tokens, and fetching user information.
    """

    @abstractmethod
    def get_authorization_url(self, state: str) -> str:
        """Generates the authorization URL for the OAuth provider.

        Args:
            state: A unique state string to protect against CSRF.

        Returns:
            The authorization URL string.
        """
        pass

    @abstractmethod
    async def exchange_auth_code(self, auth_code: str) -> Dict[str, Any]:
        """Exchanges an authorization code for access and ID tokens.

        Args:
            auth_code: The authorization code received from the OAuth provider.

        Returns:
            A dictionary containing the tokens and other related information.
        """
        pass

    @abstractmethod
    async def fetch_user_info(self, access_token: str) -> Dict[str, Any]:
        """Fetches user information from the OAuth provider using an access token.

        Args:
            access_token: The access token obtained from the OAuth provider.

        Returns:
            A dictionary containing the user's information.
        """
        pass
