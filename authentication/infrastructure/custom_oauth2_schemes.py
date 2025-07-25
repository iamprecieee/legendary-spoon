from typing import Dict

from fastapi.openapi.models import OAuthFlowPassword, OAuthFlows
from fastapi.requests import Request
from fastapi.security import OAuth2PasswordBearer


class OAuth2PasswordBearerWithEmail(OAuth2PasswordBearer):
    def __init__(
        self,
        tokenUrl: str,
        scheme_name: str | None = None,
        scopes: Dict | None = None,
        auto_error: bool = True,
    ) -> None:
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
