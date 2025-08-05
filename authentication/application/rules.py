import secrets
from typing import Tuple

from core.application.ports import CacheServiceInterface
from users.application.ports import UserRepository
from users.domain.entities import User as DomainUser

from ..domain.entities import BlacklistedToken, RefreshToken, TokenPair
from .ports import (
    BlacklistTokenRepository,
    JWTTokenServiceInterface,
    OAuthServiceInterface,
    PasswordServiceInterface,
    RefreshTokenRepository,
)


class CreateUserRule:
    """Business logic for creating a new user."""

    def __init__(
        self,
        email: str,
        password: str,
        user_repository: UserRepository,
        password_service: PasswordServiceInterface,
    ) -> None:
        self.email = email
        self.password = password
        self.user_repository = user_repository
        self.password_service = password_service

    async def execute(self) -> DomainUser:
        """Execute the user creation process.

        Returns
        -------
        DomainUser
            `DomainUser` entity of newly created user.
        """
        hashed_password = await self.password_service.hash_password(self.password)
        created_user = await self.user_repository.create(
            DomainUser(email=self.email, password=hashed_password)
        )
        return created_user


class AuthenticateUserRule:
    """Business logic for authenticating an existing user."""

    def __init__(
        self,
        email: str,
        password: str,
        user_repository: UserRepository,
        password_service: PasswordServiceInterface,
    ) -> None:
        self.email = email
        self.password = password
        self.user_repository = user_repository
        self.password_service = password_service

    async def execute(self) -> DomainUser:
        """Execute the user authentication process.

        Returns
        -------
        DomainUser
            `DomainUser` entity if authentication is successful.
        """
        existing_user = await self.user_repository.get_by_email(self.email)
        await self.password_service.check_password(
            self.password, existing_user.password
        )
        return existing_user


class LoginUserRule(AuthenticateUserRule):
    """Business logic for logging in a user.

    Extends `AuthenticateUserRule` to also handle creation and storage
    of access and refresh tokens upon successful authentication.
    """

    def __init__(
        self,
        email: str,
        password: str,
        user_repository: UserRepository,
        password_service: PasswordServiceInterface,
        token_service: JWTTokenServiceInterface,
        refresh_token_repository: RefreshTokenRepository,
    ) -> None:
        super().__init__(
            email=email,
            password=password,
            user_repository=user_repository,
            password_service=password_service,
        )
        self.token_service = token_service
        self.refresh_token_repository = refresh_token_repository

    async def execute(self) -> Tuple[DomainUser, TokenPair]:
        """Execute the user login process.

        Returns
        -------
        Tuple[DomainUser, TokenPair]
            Tuple containing `DomainUser` entity and `TokenPair`.

        Raises
        ------
        Exception
            If authentication fails (inherited from AuthenticateUserRule).
        """
        existing_user = await super().execute()
        access_token = await self.token_service.create_access_token(existing_user)
        refresh_token = await self.token_service.create_refresh_token(existing_user)
        refresh_token_entity = RefreshToken(
            token=refresh_token,
            user_id=existing_user.id,
        )
        await self.refresh_token_repository.create(refresh_token_entity)
        token_pair = TokenPair(access_token=access_token, refresh_token=refresh_token)
        return existing_user, token_pair


class CurrentUserRule:
    """Business logic for retrieving current authenticated user."""

    def __init__(
        self,
        token: str,
        token_service: JWTTokenServiceInterface,
        user_repository: UserRepository,
    ) -> None:
        self.token = token
        self.token_service = token_service
        self.user_repository = user_repository

    async def execute(self) -> DomainUser:
        """Execute the current user retrieval process.

        Returns
        -------
        DomainUser
            `DomainUser` entity corresponding to access token.

        Raises
        ------
        HTTPException
            If token is invalid or user is not found.
        """
        decoded_jwt_data = await self.token_service.decode_access_token(self.token)
        existing_user = await self.user_repository.get_by_id(decoded_jwt_data.id)
        return existing_user


class RefreshTokenRule:
    """Business logic for refreshing access and refresh tokens."""

    def __init__(
        self,
        refresh_token: str,
        user: DomainUser,
        cache_service: CacheServiceInterface,
        token_service: JWTTokenServiceInterface,
        refresh_token_repository: RefreshTokenRepository,
    ) -> None:
        self.refresh_token = refresh_token
        self.user = user
        self.cache_service = cache_service
        self.token_service = token_service
        self.refresh_token_repository = refresh_token_repository

    async def execute(self) -> Tuple[DomainUser, TokenPair]:
        """Execute the token refresh process.

        Decodes and validates refresh token, generates new access and refresh tokens,
        revokes old refresh token, stores new one, and returns user and new token pair.
        Also updates cached refresh token retrieval data.

        Returns
        -------
        Tuple[DomainUser, TokenPair]
            Tuple containing `DomainUser` entity and new `TokenPair`.

        Raises
        ------
        HTTPException
            If refresh token is invalid or expired, or user not found.
        """
        await self.token_service.decode_refresh_token(self.refresh_token)
        await self.refresh_token_repository.get_by_token(self.refresh_token)

        new_access_token = await self.token_service.create_access_token(self.user)
        new_refresh_token = await self.token_service.create_refresh_token(self.user)

        await self.refresh_token_repository.revoke_token(
            self.refresh_token, self.user.id
        )

        cache_key = self.cache_service.get_cache_key(
            "auth:token",
            "authentication.infrastructure.repositories.RefreshTokenRepository.get_by_token",
            self,  # will get skipped
            self.refresh_token,
        )
        await self.cache_service.delete(cache_key)

        new_refresh_token_entity = RefreshToken(
            token=new_refresh_token,
            user_id=self.user.id,
        )
        await self.refresh_token_repository.create(new_refresh_token_entity)

        token_pair = TokenPair(
            access_token=new_access_token, refresh_token=new_refresh_token
        )
        return self.user, token_pair


class LogoutRule:
    """Business logic for logging out a user."""

    def __init__(
        self,
        user_id: int,
        access_token: str,
        refresh_token: str | None,
        cache_service: CacheServiceInterface,
        token_service: JWTTokenServiceInterface,
        blacklist_token_repository: BlacklistTokenRepository,
        refresh_token_repository: RefreshTokenRepository,
    ) -> None:
        self.user_id = user_id
        self.access_token = access_token
        self.refresh_token = refresh_token
        self.cache_service = cache_service
        self.token_service = token_service
        self.blacklist_token_repository = blacklist_token_repository
        self.refresh_token_repository = refresh_token_repository

    async def execute(self) -> None:
        """Execute the user logout process.

        Blacklists provided access token and revokes refresh token (if present).
        Also updates cached refresh token retrieval data.
        """
        decoded_jwt_data = await self.token_service.decode_jwt_token(self.access_token)
        await self.blacklist_token_repository.create(
            BlacklistedToken(
                token=self.access_token, expires_at=decoded_jwt_data.get("exp")
            )
        )

        if self.refresh_token:
            await self.refresh_token_repository.revoke_token(
                self.refresh_token, self.user_id
            )

            cache_key = self.cache_service.get_cache_key(
                "auth:token",
                "authentication.infrastructure.repositories.RefreshTokenRepository.get_by_token",
                self,  # will get skipped
                self.refresh_token,
            )
            await self.cache_service.delete(cache_key)


class OAuthLoginRule:
    """Business logic for initiating an OAuth login flow."""

    def __init__(
        self,
        oauth_service: OAuthServiceInterface,
    ) -> None:
        self.oauth_service = oauth_service

    def execute(self) -> str:
        """Execute the OAuth login initiation process.

        Generates a unique state and constructs authorization URL for OAuth provider.

        Returns
        -------
        str
            Authorization URL string.
        """
        state = secrets.token_urlsafe(32)
        return self.oauth_service.get_authorization_url(state)


class OAuthCallbackRule:
    """Business logic for handling the OAuth callback."""

    def __init__(
        self,
        auth_code: str,
        cache_service: CacheServiceInterface,
        oauth_service: OAuthServiceInterface,
        user_repository: UserRepository,
        token_service: JWTTokenServiceInterface,
        refresh_token_repository: RefreshTokenRepository,
        password_service: PasswordServiceInterface,
    ) -> None:
        self.auth_code = auth_code
        self.cache_service = cache_service
        self.oauth_service = oauth_service
        self.user_repository = user_repository
        self.token_service = token_service
        self.refresh_token_repository = refresh_token_repository
        self.password_service = password_service

    async def execute(self) -> Tuple[DomainUser, TokenPair, bool]:
        """Execute the OAuth callback processing.

        - Exchanges authorization code for tokens
        - Fetches user info,
        - Creates or links user
        - Generates new access and refresh tokens
        - Stores refresh token
        - Returns user, token pair, and a boolean indicating new user creation.

        Creates new user with a random password if no user with provided email exists.
        Also updates cached user retrieval data.

        Returns
        -------
        Tuple[DomainUser, TokenPair, bool]
            Tuple containing `DomainUser` entity, `TokenPair`,
            and boolean (`is_new_user`) indicating if a new user was created.

        Raises
        ------
        HTTPException
            If OAuth flow fails or user information cannot be retrieved.
        """
        token_data = await self.oauth_service.exchange_auth_code(self.auth_code)
        access_token = token_data.get("access_token")

        user_info = await self.oauth_service.fetch_user_info(access_token)
        user_info.update({"id": user_info.get("sub", user_info.get("id"))})

        social_user = await self.user_repository.get_by_social_id(
            social_id=user_info["id"]
        )
        is_new_user = False

        if social_user:
            pass
        else:
            try:
                social_user = await self.user_repository.get_by_email(
                    user_info["email"]
                )
                await self.user_repository.link_social_account(
                    user_email=social_user.email, social_data=user_info
                )

                cache_key_email = self.cache_service.get_cache_key(
                    "user:email",
                    "users.infrastructure.repositories.UserRepository.get_by_email",
                    self,  # will get skipped
                    social_user.email,
                )
                cache_key_id = self.cache_service.get_cache_key(
                    "user:id",
                    "users.infrastructure.repositories.UserRepository.get_by_id",
                    self,  # will get skipped
                    social_user.id,
                )
                await self.cache_service.set(cache_key_email, social_user, 300)
                await self.cache_service.set(cache_key_id, social_user, 300)
            except Exception:
                random_password = secrets.token_urlsafe(16) + "0Zz@"
                hashed_random_password = await self.password_service.hash_password(
                    random_password
                )
                social_user = await self.user_repository.create(
                    DomainUser(
                        email=user_info["email"], password=hashed_random_password
                    )
                )
                is_new_user = True

        access_token = await self.token_service.create_access_token(social_user)
        refresh_token = await self.token_service.create_refresh_token(social_user)

        refresh_token_entity = RefreshToken(
            token=refresh_token,
            user_id=social_user.id,
        )
        await self.refresh_token_repository.create(refresh_token_entity)

        token_pair = TokenPair(access_token=access_token, refresh_token=refresh_token)

        return social_user, token_pair, is_new_user
