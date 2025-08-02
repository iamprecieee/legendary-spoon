from typing import Dict

from fastapi.openapi.models import OAuthFlowPassword, OAuthFlows
from fastapi.requests import Request
from fastapi.security import OAuth2PasswordBearer


class OAuth2PasswordBearerWithEmail(OAuth2PasswordBearer):
    """Custom OAuth2PasswordBearer scheme that includes email for OpenAPI documentation.

    This class extends `OAuth2PasswordBearer` to ensure that the token URL
    is correctly displayed in the OpenAPI documentation for password flow,
    which can implicitly involve an email for authentication.
    """

    def __init__(
        self,
        tokenUrl: str,
        scheme_name: str | None = None,
        scopes: Dict | None = None,
        auto_error: bool = True,
    ) -> None:
        """Initializes the OAuth2PasswordBearerWithEmail scheme.

        Args:
            tokenUrl: The URL where the client can obtain the access token.
            scheme_name: An optional name for the security scheme.
            scopes: A dictionary of scopes and their descriptions.
            auto_error: If True, FastAPI will automatically raise an HTTPException
                        for invalid credentials (default: True).
        """
        if not scopes:
            scopes = {}

        # This line is necessary to ensure OpenAPI docs show the password flow
        OAuthFlows(password=OAuthFlowPassword(tokenUrl=tokenUrl, scopes=scopes))

        super().__init__(
            tokenUrl=tokenUrl,
            scheme_name=scheme_name,
            scopes=scopes,
            auto_error=auto_error,
        )

    async def __call__(self, request: Request) -> str | None:
        """Extracts the token from the request using the parent class logic."""

        return await super().__call__(request)
