from typing import Tuple

from users.application.ports import UserRepository
from users.domain.entities import User as DomainUser

from ..domain.entities import BlacklistedToken, RefreshToken, TokenPair
from .ports import (
    BlacklistTokenRepository,
    JWTTokenServiceInterface,
    PasswordServiceInterface,
    RefreshTokenRepository,
)


class CreateUserRule:
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

    def execute(self) -> DomainUser:
        hashed_password = self.password_service.hash_password(self.password)
        created_user = self.user_repository.create(
            DomainUser(email=self.email, password=hashed_password)
        )
        return created_user


class AuthenticateUserRule:
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

    def execute(self) -> DomainUser | None:
        existing_user = self.user_repository.get_by_email(self.email)
        if not self.password_service.check_password(
            self.password, existing_user.password
        ):
            return None

        return existing_user


class LoginUserRule(AuthenticateUserRule):
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

    def execute(self) -> Tuple[DomainUser, TokenPair]:
        existing_user = super().execute()

        access_token = self.token_service.create_access_token(existing_user)
        refresh_token = self.token_service.create_refresh_token(existing_user)

        # Store the refresh token in the repository
        refresh_token_entity = RefreshToken(
            token=refresh_token,
            user_id=existing_user.id,
        )
        self.refresh_token_repository.create(refresh_token_entity)

        token_pair = TokenPair(access_token=access_token, refresh_token=refresh_token)

        return existing_user, token_pair


class CurrentUserRule:
    def __init__(
        self,
        token: str,
        token_service: JWTTokenServiceInterface,
        user_repository: UserRepository,
    ) -> None:
        self.token = token
        self.token_service = token_service
        self.user_repository = user_repository

    def execute(self) -> DomainUser:
        decoded_jwt_data = self.token_service.decode_access_token(self.token)
        existing_user = self.user_repository.get_by_id(decoded_jwt_data.id)
        return existing_user


class RefreshTokenRule:
    def __init__(
        self,
        refresh_token: str,
        user_repository: UserRepository,
        token_service: JWTTokenServiceInterface,
        refresh_token_repository: RefreshTokenRepository,
    ) -> None:
        self.refresh_token = refresh_token
        self.user_repository = user_repository
        self.token_service = token_service
        self.refresh_token_repository = refresh_token_repository

    def execute(self) -> Tuple[DomainUser, TokenPair]:
        payload = self.token_service.decode_refresh_token(self.refresh_token)

        # Ensure the refresh token exists and is valid
        self.refresh_token_repository.get_by_token(self.refresh_token)

        user = self.user_repository.get_by_id(payload["user_id"])

        new_access_token = self.token_service.create_access_token(user)
        new_refresh_token = self.token_service.create_refresh_token(user)

        # Revoke the old refresh token
        self.refresh_token_repository.revoke_token(self.refresh_token)

        # Store the new refresh token
        new_refresh_token_entity = RefreshToken(
            token=new_refresh_token,
            user_id=user.id,
        )
        self.refresh_token_repository.create(new_refresh_token_entity)

        token_pair = TokenPair(
            access_token=new_access_token, refresh_token=new_refresh_token
        )

        return user, token_pair


class LogoutRule:
    def __init__(
        self,
        access_token: str,
        refresh_token: str | None,
        token_service: JWTTokenServiceInterface,
        blacklist_token_repository: BlacklistTokenRepository,
        refresh_token_repository: RefreshTokenRepository,
    ) -> None:
        self.access_token = access_token
        self.refresh_token = refresh_token
        self.token_service = token_service
        self.blacklist_token_repository = blacklist_token_repository
        self.refresh_token_repository = refresh_token_repository

    def execute(self) -> None:
        decoded_jwt_data = self.token_service.decode_jwt_token(self.access_token)
        self.blacklist_token_repository.create(
            BlacklistedToken(
                token=self.access_token, expires_at=decoded_jwt_data.get("exp")
            )
        )

        if self.refresh_token:
            self.refresh_token_repository.revoke_token(self.refresh_token)
