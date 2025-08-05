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
    """Concrete implementation of `PasswordServiceInterface` for password hashing and checking."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self.pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

    async def hash_password(self, password: str) -> str:
        """Hash a raw password after enforcing strength requirements.

        Password is salted with the application's secret key before hashing.

        Parameters
        ----------
        password: str
            Plain-text password to hash.

        Returns
        -------
        str
            Securely hashed password string.

        Raises
        ------
        ValueError
            If password does not meet defined strength requirements.
        """
        self._ensure_strong_password(password)
        return self.pwd_context.hash(password)

    async def check_password(self, raw_password: str, hashed_password: str) -> bool:
        """Check if a raw password matches a hashed password.

        Raw password is salted with the application's secret key before verification.

        Parameters
        ----------
        raw_password: str
            Plain-text password to check.
        hashed_password: str
            Hashed password to compare against.

        Returns
        -------
        bool

        Raises
        ------
        ValueError
            If raw password does not meet defined strength requirements.
        HTTPException
            If raw password does not match stored hashed password.
        """
        self._ensure_strong_password(raw_password)

        if not self.pwd_context.verify(raw_password, hashed_password):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid authentication credentials",
            )

    def _ensure_strong_password(self, password: str) -> None:
        """Enforce password strength requirements.

        Checks for presence of lowercase, uppercase, digit, and special characters,
        as well as minimum length.

        Parameters
        ----------
        password: str
            Password string to validate.

        Raises
        ------
        ValueError
            If password does not meet any of the strength criteria.
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
    """Concrete implementation of `JWTTokenServiceInterface` for JWT creation and decoding."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

        if settings.algorithm == "RS256":
            self._signing_key = self._load_private_key()
            self._verification_key = self._load_public_key()
        else:
            self._signing_key = settings.secret_key
            self._verification_key = settings.secret_key

    async def create_access_token(self, user: DomainUser) -> str:
        """Create a signed JWT access token for the given user.

        Parameters
        ----------
        user: DomainUser
            DomainUser entity for whom to create the token.

        Returns
        -------
        str
            Encoded JWT access token string.
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
        """Create a signed JWT refresh token for the given user.

        Parameters
        ----------
        user: DomainUser
            DomainUser entity for whom to create the token.

        Returns
        -------
        str
            Encoded JWT refresh token string.
        """
        data_to_encode = {
            "user_id": user.id,
            "type": "refresh",
            "jti": secrets.token_urlsafe(32),
        }

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
        """Decode a raw JWT token using the configured secret key or private/public keys,
        and corresponding algorithm.

        Parameters
        ----------
        token: str
            JWT token string to decode.

        Returns
        -------
        Dict[str, Any]
            Dictionary containing the decoded token payload.

        Raises
        ------
        HTTPException
            If token is invalid or cannot be decoded.
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
        """Decode and validate an access token, returning the associated user.

        Parameters
        ----------
        token: str
            Access token string to decode and validate.

        Returns
        -------
        DomainUser
            DomainUser entity if token is valid and active.

        Raises
        ------
        HTTPException
            If token is invalid, expired, or of wrong type.
        """
        try:
            payload = await self.decode_jwt_token(token)

            if payload.get("type") != "access":
                raise InvalidTokenError
            elif datetime.fromtimestamp(
                payload.get("exp"), tz=timezone.utc
            ) < datetime.now(timezone.utc):
                raise InvalidTokenError

            payload_data = {
                "id": payload.get("user_id"),
                "email": payload.get("email"),
                "is_active": payload.get("is_active", True),
                "password": "",
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
        """Decode and validate a refresh token.

        Parameters
        ----------
        token: str
            Refresh token string to decode and validate.

        Returns
        -------
        Dict[str, Any] | None

        Raises
        ------
        HTTPException
            If token is invalid, expired, or of wrong type.
        """
        try:
            payload = await self.decode_jwt_token(token)
            if payload.get("type") != "refresh":
                raise InvalidTokenError
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
        """Load RSA private key from file specified in settings.

        Returns
        -------
        str
            Private key as a PEM-encoded string.
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
        """Load RSA public key from file specified in settings.

        Returns
        -------
        str
            Public key as a PEM-encoded string.
        """
        return self._settings.public_key_path.read_text()


class GoogleOAuthService(OAuthServiceInterface):
    """Concrete implementation of `OAuthServiceInterface` for Google OAuth 2.0."""

    def __init__(self, settings: Settings) -> None:
        """Initializes the GoogleOAuthService.

        Args:
            settings: Application settings, providing Google OAuth client ID, secret,
                      redirect URI, token URL, and user info URL.
        """
        self._settings = settings

    def get_authorization_url(self, state: str) -> str:
        """Generate Google OAuth authorization URL.

        Parameters
        ----------
        state: str
            Unique state string to protect against CSRF attacks.

        Returns
        -------
        str
            Full authorization URL for Google OAuth.
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
        """Exchange an authorization code for Google access and ID tokens.

        Parameters
        ----------
        auth_code: str
            Authorization code received from Google's OAuth callback.

        Returns
        -------
        Dict[str, Any]

        Raises
        ------
        httpx.HTTPStatusError
            If HTTP request to Google's token endpoint fails.
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
        """Fetch user profile information from Google using an access token.

        Parameters
        ----------
        access_token: str
            Access token obtained from Google.

        Returns
        -------
        Dict[str, Any]

        Raises
        ------
        httpx.HTTPStatusError
            If HTTP request to Google's user info endpoint fails.
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
