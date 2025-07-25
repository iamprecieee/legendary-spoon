import re
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Dict

import jwt
from fastapi import HTTPException, status
from jwt.exceptions import InvalidTokenError
from passlib.context import CryptContext

from config.base import Settings
from users.domain.entities import User as DomainUser

from ..application.ports import JWTTokenServiceInterface, PasswordServiceInterface


class PasswordService(PasswordServiceInterface):
    def __init__(self, settings: Settings):
        self._settings = settings
        self.pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

    def hash_password(self, password: str) -> str:
        self._ensure_strong_password(password)

        salted_password = (password + self._settings.secret_key).encode("utf-8")
        return self.pwd_context.hash(salted_password)

    def check_password(self, raw_password: str, hashed_password: str) -> bool:
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


class JWTTokenService(JWTTokenServiceInterface):
    def __init__(self, settings: Settings):
        self._settings = settings

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

        except InvalidTokenError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication token",
            )

    def decode_refresh_token(self, token: str) -> dict | None:
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

        except InvalidTokenError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token",
            )
