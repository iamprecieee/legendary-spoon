import secrets
from typing import Tuple

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
    """Encapsulates the business logic for creating a new user.

    This rule handles the process of hashing the user's password
    and persisting the new user to the database.
    """

    def __init__(
        self,
        email: str,
        password: str,
        user_repository: UserRepository,
        password_service: PasswordServiceInterface,
    ) -> None:
        """Initializes the CreateUserRule.

        Args:
            email: The email address of the user to be created.
            password: The plain-text password for the new user.
            user_repository: An instance of `UserRepository` for database operations.
            password_service: An instance of `PasswordServiceInterface` for password hashing.
        """
        self.email = email
        self.password = password
        self.user_repository = user_repository
        self.password_service = password_service

    async def execute(self) -> DomainUser:
        """Executes the user creation process.

        Hashes the provided password and saves the new user to the database.

        Returns:
            The `DomainUser` entity of the newly created user.
        """
        hashed_password = await self.password_service.hash_password(self.password)

        created_user = await self.user_repository.create(
            DomainUser(email=self.email, password=hashed_password)
        )
        return created_user


class AuthenticateUserRule:
    """Encapsulates the business logic for authenticating an existing user.

    This rule checks if the provided credentials match an existing user
    in the database.
    """

    def __init__(
        self,
        email: str,
        password: str,
        user_repository: UserRepository,
        password_service: PasswordServiceInterface,
    ) -> None:
        """Initializes the AuthenticateUserRule.

        Args:
            email: The email address of the user attempting to authenticate.
            password: The plain-text password provided by the user.
            user_repository: An instance of `UserRepository` for database operations.
            password_service: An instance of `PasswordServiceInterface` for password checking.
        """
        self.email = email
        self.password = password
        self.user_repository = user_repository
        self.password_service = password_service

    async def execute(self) -> DomainUser:
        """Executes the user authentication process.

        Retrieves the user by email and verifies the provided password
        against the stored hashed password.

        Returns:
            The `DomainUser` entity if authentication is successful.
        """
        existing_user = await self.user_repository.get_by_email(self.email)

        await self.password_service.check_password(
            self.password, existing_user.password
        )

        return existing_user


class LoginUserRule(AuthenticateUserRule):
    """Encapsulates the business logic for logging in a user.

    Extends `AuthenticateUserRule` to also handle the creation and storage
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
        """Initializes the LoginUserRule.

        Args:
            email: The email address of the user attempting to log in.
            password: The plain-text password provided by the user.
            user_repository: An instance of `UserRepository` for database operations.
            password_service: An instance of `PasswordServiceInterface` for password checking.
            token_service: An instance of `JWTTokenServiceInterface` for token creation.
            refresh_token_repository: An instance of `RefreshTokenRepository` for storing refresh tokens.
        """
        super().__init__(
            email=email,
            password=password,
            user_repository=user_repository,
            password_service=password_service,
        )
        self.token_service = token_service
        self.refresh_token_repository = refresh_token_repository

    async def execute(self) -> Tuple[DomainUser, TokenPair]:
        """Executes the user login process.

        Authenticates the user, creates access and refresh tokens,
        stores the refresh token, and returns both the user and token pair.

        Returns:
            A tuple containing the `DomainUser` entity and a `TokenPair`.

        Raises:
            Exception: If authentication fails (inherited from AuthenticateUserRule).
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
    """Encapsulates the business logic for retrieving the current authenticated user.

    This rule decodes an access token to identify and fetch the corresponding user.
    """

    def __init__(
        self,
        token: str,
        token_service: JWTTokenServiceInterface,
        user_repository: UserRepository,
    ) -> None:
        """Initializes the CurrentUserRule.

        Args:
            token: The access token of the current user.
            token_service: An instance of `JWTTokenServiceInterface` for token decoding.
            user_repository: An instance of `UserRepository` for fetching user details.
        """
        self.token = token
        self.token_service = token_service
        self.user_repository = user_repository

    async def execute(self) -> DomainUser:
        """Executes the current user retrieval process.

        Decodes the access token, extracts the user ID, and fetches
        the user from the repository.

        Returns:
            The `DomainUser` entity corresponding to the access token.

        Raises:
            HTTPException: If the token is invalid or the user is not found.
        """
        decoded_jwt_data = await self.token_service.decode_access_token(self.token)
        existing_user = await self.user_repository.get_by_id(decoded_jwt_data.id)
        return existing_user


class RefreshTokenRule:
    """Encapsulates the business logic for refreshing access and refresh tokens.

    This rule handles the process of validating an old refresh token,
    generating new tokens, revoking the old refresh token, and storing the new one.
    """

    def __init__(
        self,
        refresh_token: str,
        user: DomainUser,
        token_service: JWTTokenServiceInterface,
        refresh_token_repository: RefreshTokenRepository,
    ) -> None:
        """Initializes the RefreshTokenRule.

        Args:
            refresh_token: The old refresh token string.
            user: An instance of `DomainUser` containing user details.
            token_service: An instance of `JWTTokenServiceInterface` for token creation and decoding.
            refresh_token_repository: An instance of `RefreshTokenRepository` for managing refresh tokens.
        """
        self.refresh_token = refresh_token
        self.user = user
        self.token_service = token_service
        self.refresh_token_repository = refresh_token_repository

    async def execute(self) -> Tuple[DomainUser, TokenPair]:
        """Executes the token refresh process.

        Decodes and validates the refresh token, generates new access and refresh tokens,
        revokes the old refresh token, stores the new one, and returns the user and new token pair.

        Returns:
            A tuple containing the `DomainUser` entity and the new `TokenPair`.

        Raises:
            HTTPException: If the refresh token is invalid or expired, or user not found.
        """
        await self.token_service.decode_refresh_token(self.refresh_token)

        # Ensure the refresh token exists and is valid
        await self.refresh_token_repository.get_by_token(self.refresh_token)

        new_access_token = await self.token_service.create_access_token(self.user)
        new_refresh_token = await self.token_service.create_refresh_token(self.user)

        # Revoke the old refresh token
        await self.refresh_token_repository.revoke_token(
            self.refresh_token, self.user.id
        )

        # Store the new refresh token
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
    """Encapsulates the business logic for logging out a user.

    This rule blacklists the access token and revokes the refresh token (if provided).
    """

    def __init__(
        self,
        user_id: int,
        access_token: str,
        refresh_token: str | None,
        token_service: JWTTokenServiceInterface,
        blacklist_token_repository: BlacklistTokenRepository,
        refresh_token_repository: RefreshTokenRepository,
    ) -> None:
        """Initializes the LogoutRule.

        Args:
            user_id: The id of the authenticated user.
            access_token: The access token to be blacklisted.
            refresh_token: The refresh token to be revoked (optional).
            token_service: An instance of `JWTTokenServiceInterface` for token decoding.
            blacklist_token_repository: An instance of `BlacklistTokenRepository` for blacklisting access tokens.
            refresh_token_repository: An instance of `RefreshTokenRepository` for revoking refresh tokens.
        """
        self.user_id = user_id
        self.access_token = access_token
        self.refresh_token = refresh_token
        self.token_service = token_service
        self.blacklist_token_repository = blacklist_token_repository
        self.refresh_token_repository = refresh_token_repository

    async def execute(self) -> None:
        """Executes the user logout process.

        Blacklists the provided access token and revokes the refresh token (if present).
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


class OAuthLoginRule:
    """Encapsulates the business logic for initiating an OAuth login flow.

    This rule generates an authorization URL for an OAuth provider.
    """

    def __init__(
        self,
        oauth_service: OAuthServiceInterface,
    ) -> None:
        """Initializes the OAuthLoginRule.

        Args:
            oauth_service: An instance of `OAuthServiceInterface` for generating authorization URLs.
        """
        self.oauth_service = oauth_service

    def execute(self) -> str:
        """Executes the OAuth login initiation process.

        Generates a unique state and constructs the authorization URL for the OAuth provider.

        Returns:
            The authorization URL string.
        """
        import secrets

        state = secrets.token_urlsafe(32)
        return self.oauth_service.get_authorization_url(state)


class OAuthCallbackRule:
    """Encapsulates the business logic for handling the OAuth callback.

    This rule processes the authorization code, exchanges it for tokens,
    fetches user information, and either creates a new user or links an existing one.
    It also handles token generation and storage.
    """

    def __init__(
        self,
        auth_code: str,
        oauth_service: OAuthServiceInterface,
        user_repository: UserRepository,
        token_service: JWTTokenServiceInterface,
        refresh_token_repository: RefreshTokenRepository,
        password_service: PasswordServiceInterface,
    ) -> None:
        """Initializes the OAuthCallbackRule.

        Args:
            auth_code: The authorization code received from the OAuth provider.
            oauth_service: An instance of `OAuthServiceInterface` for OAuth operations.
            user_repository: An instance of `UserRepository` for user management.
            token_service: An instance of `JWTTokenServiceInterface` for token creation.
            refresh_token_repository: An instance of `RefreshTokenRepository` for storing refresh tokens.
            password_service: An instance of `PasswordServiceInterface` for password hashing.
        """
        self.auth_code = auth_code
        self.oauth_service = oauth_service
        self.user_repository = user_repository
        self.token_service = token_service
        self.refresh_token_repository = refresh_token_repository
        self.password_service = password_service

    async def execute(self) -> Tuple[DomainUser, TokenPair, bool]:
        """Executes the OAuth callback processing.

        Exchanges the authorization code for tokens, fetches user info,
        creates or links the user, generates new access and refresh tokens,
        stores the refresh token, and returns the user, token pair, and a boolean
        indicating if a new user was created.

        Returns:
            A tuple containing the `DomainUser` entity, a `TokenPair`,
            and a boolean (`is_new_user`) indicating if a new user was created.

        Raises:
            HTTPException: If OAuth flow fails or user information cannot be retrieved.
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
            except Exception:
                # If user with this email exists but no social account linked, create new user
                # with a random password since it's an OAuth flow
                random_password = secrets.token_urlsafe(16) + "@"
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

        # Store the refresh token in the repository
        refresh_token_entity = RefreshToken(
            token=refresh_token,
            user_id=social_user.id,
        )
        await self.refresh_token_repository.create(refresh_token_entity)

        token_pair = TokenPair(access_token=access_token, refresh_token=refresh_token)

        return social_user, token_pair, is_new_user
