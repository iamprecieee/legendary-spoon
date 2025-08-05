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
        """Hash a raw password.

        Parameters
        ----------
        password: str
            Plain-text password to hash.

        Returns
        -------
        str
            Hashed password string.
        """
        pass

    @abstractmethod
    async def check_password(self, raw_password: str, hashed_password: str) -> bool:
        """Check if a raw password matches a hashed password.

        Parameters
        ----------
        raw_password: str
            Plain-text password to check.
        hashed_password: str
            Hashed password to compare against.

        Returns
        -------
        bool
            `True` if the passwords match, `False` otherwise.
        """
        pass


class JWTTokenServiceInterface(ABC):
    """Abstract base class for JSON Web Token (JWT) related services.

    Defines the interface for creating and decoding JWT access and refresh tokens.
    """

    @abstractmethod
    async def create_access_token(self, user: DomainUser) -> str:
        """Create a new JWT access token for a given user.

        Parameters
        ----------
        user: DomainUser
            Domain user entity for whom the token is created.

        Returns
        -------
        str
            Encoded JWT access token string.
        """
        pass

    @abstractmethod
    async def create_refresh_token(self, user: DomainUser) -> str:
        """Create a new JWT refresh token for a given user.

        Parameters
        ----------
        user: DomainUser
            Domain user entity for whom the token is created.

        Returns
        -------
        str
            Encoded JWT refresh token string.
        """
        pass

    @abstractmethod
    async def decode_jwt_token(self, token: str) -> Dict[str, Any]:
        """Decode a given JWT token without specific validation.

        Parameters
        ----------
        token: str
            JWT token string to decode.

        Returns
        -------
        Dict[str, Any]
            Dictionary containing decoded token payload.
        """
        pass

    @abstractmethod
    async def decode_access_token(self, token: str) -> DomainUser | None:
        """Decode and validates a JWT access token.

        Parameters
        ----------
        token: str
            JWT access token string to decode.

        Returns
        -------
        DomainUser | None
            `DomainUser` entity if the token is valid, otherwise None.
        """
        pass

    @abstractmethod
    async def decode_refresh_token(self, token: str) -> Dict[str, Any] | None:
        """Decode and validates a JWT refresh token.

        Parameters
        ----------
        token: str
            JWT refresh token string to decode.

        Returns
        -------
        Dict[str, Any] | None
            Dictionary containing decoded token payload if valid, otherwise None.
        """
        pass


class RefreshTokenRepository(ABC):
    """Abstract base class for managing refresh tokens in the repository.

    Defines the interface for creating, retrieving, and revoking refresh tokens.
    """

    @abstractmethod
    async def create(self, refresh_token: DomainRefreshToken) -> DomainRefreshToken:
        """Create a new refresh token in the repository.

        Parameters
        ----------
        refresh_token: DomainRefreshToken
            `DomainRefreshToken` entity to create.

        Returns
        -------
        str
            Created `DomainRefreshToken` entity.
        """
        pass

    @abstractmethod
    async def get_by_token(
        self, token: str, raise_error: bool = False
    ) -> DomainRefreshToken:
        """Retrieves a refresh token by its string value.

        Parameters
        ----------
        token: str
            Refresh token string.
        raise_error: bool, default=False
            If `True`, raises an error if the token is not found.

        Returns
        -------
        str
            `DomainRefreshToken` entity.
        """
        pass

    @abstractmethod
    async def revoke_token(self, token: str, user_id: int) -> None:
        """Revokes a refresh token, making it unusable.

        Parameters
        ----------
        token: str
            Refresh token string to revoke.
        user_id: int
            ID for user associated with the token to be revoked.
        """
        pass


class BlacklistTokenRepository(ABC):
    """Abstract base class for managing blacklisted tokens in the repository.

    Defines the interface for blacklisting tokens and checking if a token is blacklisted.
    """

    @abstractmethod
    async def create(self, token: DomainBlacklistedToken) -> None:
        """Add a token to the blacklist.

        Parameters
        ----------
        token: DomainBlacklistedToken
            `DomainBlacklistedToken` entity to blacklist.
        """
        pass

    @abstractmethod
    async def is_token_blacklisted(self, token: str, raise_error: bool = False) -> bool:
        """Check if a token is present in the blacklist.

        Parameters
        ----------
        token: str
            Token string to check.
        raise_error: bool, default=False
            If `True`, raises an error if the token is found in the blacklist.

        Returns
        -------
        str
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
        """Generate the authorization URL for the OAuth provider.

        Parameters
        ----------
        state: str
            Unique state string to protect against CSRF.

        Returns
        -------
        str
            Authorization URL string.
        """
        pass

    @abstractmethod
    async def exchange_auth_code(self, auth_code: str) -> Dict[str, Any]:
        """Exchange an authorization code for access and ID tokens.

        Parameters
        ----------
        auth_code: str
            Authorization code received from the OAuth provider.

        Returns
        -------
        Dict[str, Any]
            Dictionary containing tokens and other related information.
        """
        pass

    @abstractmethod
    async def fetch_user_info(self, access_token: str) -> Dict[str, Any]:
        """Fetch user information from the OAuth provider using an access token.

        Parameters
        ----------
        access_token: str
            Access token obtained from the OAuth provider.

        Returns
        -------
        Dict[str, Any]
            Dictionary containing user's information.
        """
        pass
