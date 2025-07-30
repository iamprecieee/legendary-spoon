import json
import re
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Dict

import httpx
import jwt
from fastapi import HTTPException, status
from jwt.exceptions import InvalidTokenError
from loguru import logger
from passlib.context import CryptContext

from config.base import Settings
from users.domain.entities import User as DomainUser

from ..application.ports import (
    JWTTokenServiceInterface,
    OAuthServiceInterface,
    PasswordServiceInterface,
)


class PasswordService(PasswordServiceInterface):
    def __init__(self, settings: Settings):
        self._settings = settings
        self.pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

    def hash_password(self, password: str) -> str:
        self._ensure_strong_password(password)

        salted_password = (password + self._settings.secret_key).encode("utf-8")
        return self.pwd_context.hash(salted_password)

    def check_password(self, raw_password: str, hashed_password: str) -> bool:
        self._ensure_strong_password(raw_password)

        salted_password = (raw_password + self._settings.secret_key).encode("utf-8")
        return self.pwd_context.verify(salted_password, hashed_password)

    def _ensure_strong_password(self, password: str) -> None:
        if not re.search(r"[a-z]", password):
            raise ValueError("Password must contain at least one lowercase letter.")

        if not re.search(r"[A-Z]", password):
            raise ValueError("Password must contain at least one uppercase letter.")

        if not re.search(r"\d", password):
            raise ValueError("Password must contain at least one digit.")

        if not re.search(r"[!@#$%^&*()+\-=\;':,.<>?~]", password):
            raise ValueError("Password must contain at least one special character.")

        if len(password) < self._settings.min_password_length:
            raise ValueError(
                f"Password must be at least {self._settings.min_password_length} characters long."
            )


class JWTTokenService(JWTTokenServiceInterface):
    def __init__(self, settings: Settings, sanitizer: Any):
        self._settings = settings
        self.sanitizer = sanitizer

    def create_access_token(self, user: DomainUser) -> str:
        data_to_encode = {
            "user_id": user.id,
            "email": user.email,
            "is_active": user.is_active,
            "type": "access",
        }

        # Set token expiry time
        expiry = datetime.now(timezone.utc) + timedelta(
            minutes=self._settings.access_token_expiry
        )
        data_to_encode.update({"exp": expiry})

        return jwt.encode(
            data_to_encode,
            self._settings.secret_key,
            algorithm=self._settings.algorithm,
        )

    def create_refresh_token(self, user: DomainUser) -> str:
        data_to_encode = {
            "user_id": user.id,
            "type": "refresh",
            "jti": secrets.token_urlsafe(32),
        }

        # Set refresh token expiry time
        expiry = datetime.now(timezone.utc) + timedelta(
            days=self._settings.refresh_token_expiry
        )
        data_to_encode.update({"exp": expiry})

        return jwt.encode(
            data_to_encode,
            self._settings.secret_key,
            algorithm=self._settings.algorithm,
        )

    def decode_jwt_token(self, token: str) -> Dict[str, Any]:
        try:
            return jwt.decode(
                token, self._settings.secret_key, algorithms=[self._settings.algorithm]
            )
        except InvalidTokenError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication token",
            )

    def decode_access_token(self, token: str) -> DomainUser | None:
        try:
            payload = self.decode_jwt_token(token)
            if payload.get("type") != "access":
                raise InvalidTokenError
            # Check token expiration
            elif datetime.fromtimestamp(
                payload.get("exp"), tz=timezone.utc
            ) < datetime.now(timezone.utc):
                raise InvalidTokenError

            payload_data = {
                "id": payload.get("user_id"),
                "email": payload.get("email"),
                "is_active": payload.get("is_active", True),
                "password": "",  # Password is not included in token
            }

            return DomainUser(**payload_data)

        except InvalidTokenError as e:
            logger.error(
                f"❌ Invalid access token: {self.sanitizer.sanitize_exception_for_logging(e)}"
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication token",
            ) from e

    def decode_refresh_token(self, token: str) -> Dict[str, Any] | None:
        try:
            payload = self.decode_jwt_token(token)
            if payload.get("type") != "refresh":
                raise InvalidTokenError
            # Check token expiration
            elif datetime.fromtimestamp(
                payload.get("exp"), tz=timezone.utc
            ) < datetime.now(timezone.utc):
                raise InvalidTokenError

            return payload

        except InvalidTokenError as e:
            logger.error(
                f"❌ Invalid refresh token: {self.sanitizer.sanitize_exception_for_logging(e)}"
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token",
            ) from e


class GoogleOAuthService(OAuthServiceInterface):
    def __init__(self, settings: Settings, sanitizer: Any) -> None:
        self._settings = settings
        self.sanitizer = sanitizer

    def get_authorization_url(self, state: str) -> str:
        return (
            f"https://accounts.google.com/o/oauth2/auth?response_type=code"
            f"&client_id={self._settings.google_client_id}"
            f"&redirect_uri={self._settings.google_redirect_uri}"
            f"&scope=email%20profile"
            f"&state={state}"
            f"&access_type=offline"
            f"&prompt=consent"
        )

    async def exchange_auth_code(self, auth_code: str) -> Dict[str, Any]:
        async with httpx.AsyncClient() as client:
            try:
                response = await client.post(
                    self._get_google_token_url(),
                    data={
                        "code": auth_code,
                        "client_id": self._settings.google_client_id,
                        "client_secret": self._settings.google_client_secret,
                        "redirect_uri": self._settings.google_redirect_uri,
                        "grant_type": "authorization_code",
                    },
                )

                response.raise_for_status()
                return response.json()

            except httpx.HTTPStatusError as e:
                logger.error(
                    f"⛓️‍💥 Error exchanging auth code: {self.sanitizer.sanitize_exception_for_logging(e)}"
                )
                logger.error(
                    f"Response content: {self.sanitizer.sanitize_exception_for_logging(json.loads(e.response.text)) if hasattr(e, 'response') else 'No response content'}"
                )
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Failed to exchange authorization code",
                ) from e

    async def fetch_user_info(self, access_token: str) -> Dict[str, Any]:
        async with httpx.AsyncClient() as client:
            try:
                response = await client.get(
                    self._get_google_user_info_url(),
                    headers={"Authorization": f"Bearer {access_token}"},
                )
                response.raise_for_status()
                return response.json()

            except httpx.HTTPStatusError as e:
                logger.error(
                    f"📄 Error fetching user info: {self.sanitizer.sanitize_exception_for_logging(e)}"
                )
                logger.error(
                    f"Response content: {self.sanitizer.sanitize_exception_for_logging(json.loads(e.response.text)) if hasattr(e, 'response') else 'No response content'}"
                )
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Failed to fetch user information",
                ) from e

    def _get_google_token_url(self) -> str:
        return "https://oauth2.googleapis.com/token"

    def _get_google_user_info_url(self) -> str:
        return "https://www.googleapis.com/oauth2/v3/userinfo"
