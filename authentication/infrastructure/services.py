import re
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Dict

import httpx
import jwt
from cryptography.hazmat.primitives import serialization
from fastapi import HTTPException, status
from jwt.exceptions import InvalidTokenError
from passlib.context import CryptContext

from config.base import Settings
from users.domain.entities import User as DomainUser

from ..application.ports import (
    JWTTokenServiceInterface,
    OAuthServiceInterface,
    PasswordServiceInterface,
)


class PasswordService(PasswordServiceInterface):
    """Concrete implementation of `PasswordServiceInterface` for password hashing and checking.

    Utilizes `passlib`'s `CryptContext` with the bcrypt scheme for secure password management.
    """

    def __init__(self, settings: Settings) -> None:
        """Initializes the PasswordService.

        Args:
            settings: Application settings, providing `secret_key` and `min_password_length`.
        """
        self._settings = settings
        self.pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

    async def hash_password(self, password: str) -> str:
        """Hashes a raw password after enforcing strength requirements.

        The password is salted with the application's secret key before hashing.

        Args:
            password: The plain-text password to hash.

        Returns:
            The securely hashed password string.

        Raises:
            ValueError: If the password does not meet the defined strength requirements.
        """
        self._ensure_strong_password(password)
        return self.pwd_context.hash(password)

    async def check_password(self, raw_password: str, hashed_password: str) -> bool:
        """Checks if a raw password matches a hashed password.

        The raw password is salted with the application's secret key before verification.

        Args:
            raw_password: The plain-text password to check.
            hashed_password: The hashed password to compare against.

        Returns:
            True if the passwords match, False otherwise.

        Raises:
            ValueError: If the raw password does not meet the defined strength requirements.
            HTTPException: If the raw password does not match stored hashed password.
        """
        self._ensure_strong_password(raw_password)

        if not self.pwd_context.verify(raw_password, hashed_password):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid authentication credentials",
            )

    def _ensure_strong_password(self, password: str) -> None:
        """Enforces password strength requirements.

        Checks for presence of lowercase, uppercase, digit, and special characters,
        as well as minimum length.

        Args:
            password: The password string to validate.

        Raises:
            ValueError: If the password does not meet any of the strength criteria.
        """
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
    """Concrete implementation of `JWTTokenServiceInterface` for JWT creation and decoding.

    Handles the encoding and decoding of access and refresh tokens using PyJWT.
    """

    def __init__(self, settings: Settings) -> None:
        """Initializes the JWTTokenService.

        Args:
            settings: Application settings, providing either`secret_key` or `private`/`public` keys, `algorithm`,
                      `access_token_expiry`, and `refresh_token_expiry`.
        """
        self._settings = settings

        if settings.algorithm == "RS256":
            self._signing_key = self._load_private_key()
            self._verification_key = self._load_public_key()
        else:
            self._signing_key = settings.secret_key
            self._verification_key = settings.secret_key

    async def create_access_token(self, user: DomainUser) -> str:
        """Creates a signed JWT access token for the given user.

        The token includes user ID, email, and active status, and is set to expire
        according to `access_token_expiry` in settings.

        Args:
            user: The `DomainUser` entity for whom to create the token.

        Returns:
            The encoded JWT access token string.
        """
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
            self._signing_key,
            algorithm=self._settings.algorithm,
        )

    async def create_refresh_token(self, user: DomainUser) -> str:
        """Creates a signed JWT refresh token for the given user.

        The token includes user ID, a unique JTI, and is set to expire
        according to `refresh_token_expiry` in settings.

        Args:
            user: The `DomainUser` entity for whom to create the token.

        Returns:
            The encoded JWT refresh token string.
        """
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
            self._signing_key,
            algorithm=self._settings.algorithm,
        )

    async def decode_jwt_token(self, token: str) -> Dict[str, Any]:
        """Decodes a raw JWT token using the configured secret key or private/public keys, and algorithm.

        This method performs basic decoding but does not validate token type or expiration.

        Args:
            token: The JWT token string to decode.

        Returns:
            A dictionary containing the decoded token payload.

        Raises:
            HTTPException: If the token is invalid or cannot be decoded.
        """
        try:
            return jwt.decode(
                token, self._verification_key, algorithms=[self._settings.algorithm]
            )
        except InvalidTokenError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Failed to decode JWT token",
            )

    async def decode_access_token(self, token: str) -> DomainUser | None:
        """Decodes and validates an access token, returning the associated user.

        Checks token type, expiration, and extracts user information.

        Args:
            token: The access token string to decode and validate.

        Returns:
            The `DomainUser` entity if the token is valid and active.

        Raises:
            HTTPException: If the token is invalid, expired, or of the wrong type.
        """
        try:
            payload = await self.decode_jwt_token(token)
            
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
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Failed to decode access token",
            ) from e

        except Exception as e:
            raise e

    async def decode_refresh_token(self, token: str) -> Dict[str, Any] | None:
        """Decodes and validates a refresh token.

        Checks token type and expiration.

        Args:
            token: The refresh token string to decode and validate.

        Returns:
            A dictionary containing the decoded token payload if valid.

        Raises:
            HTTPException: If the token is invalid, expired, or of the wrong type.
        """
        try:
            payload = await self.decode_jwt_token(token)
            if payload.get("type") != "refresh":
                raise InvalidTokenError
            # Check token expiration
            elif datetime.fromtimestamp(
                payload.get("exp"), tz=timezone.utc
            ) < datetime.now(timezone.utc):
                raise InvalidTokenError

            return payload

        except InvalidTokenError as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Failed to decode refresh token",
            ) from e

    def _load_private_key(self) -> str:
        """
        Loads the RSA private key from the file specified in settings.

        Returns:
            The private key as a PEM-encoded string.
        """
        key_content = self._settings.private_key_path.read_bytes()
        private_key = serialization.load_pem_private_key(
            key_content,
            password=self._settings.private_key_password.encode(encoding="utf-8"),
        )
        pem_private_key = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        return pem_private_key.decode(encoding="utf-8")

    def _load_public_key(self) -> str:
        """
        Loads the RSA public key from the file specified in settings.

        Returns:
            The public key as a PEM-encoded string.
        """
        return self._settings.public_key_path.read_text()


class GoogleOAuthService(OAuthServiceInterface):
    """Concrete implementation of `OAuthServiceInterface` for Google OAuth 2.0.

    Handles generating authorization URLs, exchanging authorization codes for tokens,
    and fetching user information from Google's API.
    """

    def __init__(self, settings: Settings) -> None:
        """Initializes the GoogleOAuthService.

        Args:
            settings: Application settings, providing Google OAuth client ID, secret,
                      redirect URI, token URL, and user info URL.
        """
        self._settings = settings

    def get_authorization_url(self, state: str) -> str:
        """Generates the Google OAuth authorization URL.

        Args:
            state: A unique state string to protect against CSRF attacks.

        Returns:
            The full authorization URL for Google OAuth.
        """
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
        """Exchanges an authorization code for Google access and ID tokens.

        Args:
            auth_code: The authorization code received from Google's OAuth callback.

        Returns:
            A dictionary containing the token response from Google.

        Raises:
            httpx.HTTPStatusError: If the HTTP request to Google's token endpoint fails.
        """
        async with httpx.AsyncClient() as client:
            try:
                response = await client.post(
                    self._settings.google_token_url,
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
                raise e

    async def fetch_user_info(self, access_token: str) -> Dict[str, Any]:
        """Fetches user profile information from Google using an access token.

        Args:
            access_token: The access token obtained from Google.

        Returns:
            A dictionary containing the user's profile information.

        Raises:
            httpx.HTTPStatusError: If the HTTP request to Google's user info endpoint fails.
        """
        async with httpx.AsyncClient() as client:
            try:
                response = await client.get(
                    self._settings.google_user_info_url,
                    headers={"Authorization": f"Bearer {access_token}"},
                )
                response.raise_for_status()
                return response.json()

            except httpx.HTTPStatusError as e:
                raise e
