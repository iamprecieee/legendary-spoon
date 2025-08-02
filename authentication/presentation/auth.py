from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm

from core.presentation.responses import CreatedResponse, SuccessResponse
from users.infrastructure.factory import get_user_repository

from ..application.rules import (
    CreateUserRule,
    LoginUserRule,
    LogoutRule,
    OAuthCallbackRule,
    OAuthLoginRule,
    RefreshTokenRule,
)
from ..infrastructure.factory import (
    get_blacklist_token_repository,
    get_current_user,
    get_google_oauth_service,
    get_jwt_token_service,
    get_password_service,
    get_refresh_token_repository,
    oauth2_scheme,
)
from .requests import LogoutRequest, RefreshRequest, UserCreateRequest, UserLoginRequest
from .responses import LoginResponse, OAuthLoginResponse, TokenResponse, UserResponse

router = APIRouter(prefix="/auth")


@router.post("/register", response_model=CreatedResponse, status_code=201)
async def create_user(
    request: UserCreateRequest,
    user_repository=Depends(get_user_repository),
    password_service=Depends(get_password_service),
):
    """Registers a new user with the provided email and password.

    Args:
        request: The `UserCreateRequest` containing the user's email and password.
        user_repository: Dependency-injected user repository.
        password_service: Dependency-injected password service for hashing passwords.

    Returns:
        A `CreatedResponse` indicating successful user creation,
        containing the newly created user's data.
    """
    create_user_rule = CreateUserRule(
        email=request.email,
        password=request.password,
        user_repository=user_repository,
        password_service=password_service,
    )
    created_user = await create_user_rule.execute()

    return CreatedResponse(
        data=UserResponse(**created_user.__dict__), message="User creation successful"
    )


@router.post("/login", response_model=SuccessResponse, status_code=200)
async def login_user(
    request: UserLoginRequest,
    user_repository=Depends(get_user_repository),
    password_service=Depends(get_password_service),
    token_service=Depends(get_jwt_token_service),
    refresh_token_repository=Depends(get_refresh_token_repository),
):
    """Authenticates a user and provides access and refresh tokens upon successful login.

    Args:
        request: The `UserLoginRequest` containing the user's email and password.
        user_repository: Dependency-injected user repository.
        password_service: Dependency-injected password service for checking passwords.
        token_service: Dependency-injected JWT token service for creating tokens.
        refresh_token_repository: Dependency-injected refresh token repository for storing tokens.

    Returns:
        A `SuccessResponse` containing user data and the generated access and refresh tokens.

    Raises:
        HTTPException: If authentication fails (e.g., incorrect credentials).
    """
    login_user_rule = LoginUserRule(
        email=request.email,
        password=request.password,
        user_repository=user_repository,
        password_service=password_service,
        token_service=token_service,
        refresh_token_repository=refresh_token_repository,
    )

    login_data = await login_user_rule.execute()
    if not login_data:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="User login failed"
        )

    user_data, token_data = login_data
    return SuccessResponse(
        data=LoginResponse(**user_data.__dict__, **token_data.__dict__),
        message="User login successful",
    )


@router.post("/refresh", response_model=SuccessResponse, status_code=200)
async def refresh_token(
    request: RefreshRequest,
    user_repository=Depends(get_user_repository),
    token_service=Depends(get_jwt_token_service),
    refresh_token_repository=Depends(get_refresh_token_repository),
    current_user=Depends(get_current_user),
):
    """Refreshes an expired access token using a valid refresh token.

    Args:
        request: The `RefreshRequest` containing the refresh token.
        user_repository: Dependency-injected user repository.
        token_service: Dependency-injected JWT token service for token operations.
        refresh_token_repository: Dependency-injected refresh token repository for validating and revoking tokens.

    Returns:
        A `SuccessResponse` containing new access and refresh tokens, and user data.

    Raises:
        HTTPException: If the refresh token is invalid or expired.
    """
    refresh_rule = RefreshTokenRule(
        refresh_token=request.refresh_token,
        user=current_user,
        token_service=token_service,
        refresh_token_repository=refresh_token_repository,
    )

    refresh_data = await refresh_rule.execute()
    if not refresh_data:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Token refresh failed"
        )

    user_data, token_data = refresh_data
    return SuccessResponse(
        data=LoginResponse(**user_data.__dict__, **token_data.__dict__),
        message="Token refreshed successfully",
    )


@router.post("/token", response_model=TokenResponse, include_in_schema=False)
async def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(),
    user_repository=Depends(get_user_repository),
    password_service=Depends(get_password_service),
    token_service=Depends(get_jwt_token_service),
    refresh_token_repository=Depends(get_refresh_token_repository),
):
    """Authenticates a user for OAuth2 password flow and returns an access token.

    This endpoint is typically used by clients implementing the OAuth2 password grant type.
    It's excluded from OpenAPI schema as it's primarily for machine-to-machine communication
    or specific client integrations.

    Args:
        form_data: OAuth2 form data containing username (email) and password.
        user_repository: Dependency-injected user repository.
        password_service: Dependency-injected password service for checking passwords.
        token_service: Dependency-injected JWT token service for creating tokens.
        refresh_token_repository: Dependency-injected refresh token repository for storing tokens.

    Returns:
        A `TokenResponse` containing the access token and other token details.

    Raises:
        HTTPException: If authentication fails (e.g., incorrect credentials).
    """
    login_user_rule = LoginUserRule(
        email=form_data.username,
        password=form_data.password,
        user_repository=user_repository,
        password_service=password_service,
        token_service=token_service,
        refresh_token_repository=refresh_token_repository,
    )

    login_data = await login_user_rule.execute()
    if not login_data:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
        )

    _, token_data = login_data
    return TokenResponse(**token_data.__dict__)


@router.post("/logout", response_model=SuccessResponse, status_code=200)
async def logout_user(
    request: LogoutRequest,
    access_token: str = Depends(oauth2_scheme),
    token_service=Depends(get_jwt_token_service),
    refresh_token_repository=Depends(get_refresh_token_repository),
    blacklist_token_repository=Depends(get_blacklist_token_repository),
    current_user=Depends(get_current_user),
):
    """Logs out the current user by blacklisting their access token and revoking their refresh token.

    Args:
        request: The `LogoutRequest` containing the refresh token to be revoked (optional).
        access_token: The current access token, extracted from the Authorization header.
        token_service: Dependency-injected JWT token service for token decoding.
        refresh_token_repository: Dependency-injected refresh token repository.
        blacklist_token_repository: Dependency-injected blacklist token repository.
        current_user: Dependency-injected current authenticated user (ensures user is logged in).

    Returns:
        A `SuccessResponse` indicating successful logout.
    """
    logout_rule = LogoutRule(
        user_id=current_user.id,
        access_token=access_token,
        refresh_token=request.refresh_token,
        token_service=token_service,
        blacklist_token_repository=blacklist_token_repository,
        refresh_token_repository=refresh_token_repository,
    )

    await logout_rule.execute()

    return SuccessResponse(
        data={"message": "Logged out successfully"}, message="Logout successful"
    )


@router.get("/google/login", response_model=SuccessResponse, status_code=200)
async def google_login(
    oauth_service=Depends(get_google_oauth_service),
):
    """Initiates the Google OAuth 2.0 login flow.

    Redirects the user to Google's authentication page to grant permissions.

    Args:
        oauth_service: Dependency-injected Google OAuth service.

    Returns:
        A `SuccessResponse` containing the Google authorization URL.
    """
    google_login_rule = OAuthLoginRule(oauth_service=oauth_service)
    oauth_url = google_login_rule.execute()
    return SuccessResponse(
        data=OAuthLoginResponse(oauth_url=oauth_url),
        message="Redirect to the OAuth provider for login.",
    )


@router.get("/google/callback", response_model=SuccessResponse, status_code=200)
async def google_callback(
    code: str,
    oauth_service=Depends(get_google_oauth_service),
    user_repository=Depends(get_user_repository),
    token_service=Depends(get_jwt_token_service),
    refresh_token_repository=Depends(get_refresh_token_repository),
    password_service=Depends(get_password_service),
):
    """Handles the callback from Google OAuth 2.0 after user authentication.

    Exchanges the authorization code for tokens, fetches user information,
    creates a new user if necessary, and logs them in.

    Args:
        code: The authorization code received from Google.
        oauth_service: Dependency-injected Google OAuth service.
        user_repository: Dependency-injected user repository.
        token_service: Dependency-injected JWT token service.
        refresh_token_repository: Dependency-injected refresh token repository.
        password_service: Dependency-injected password service.

    Returns:
        A `SuccessResponse` containing user data and access/refresh tokens,
        with a message indicating if a new user was created.
    """
    oauth_callback_rule = OAuthCallbackRule(
        auth_code=code,
        oauth_service=oauth_service,
        user_repository=user_repository,
        token_service=token_service,
        refresh_token_repository=refresh_token_repository,
        password_service=password_service,
    )

    user_data, token_data, is_new_user = await oauth_callback_rule.execute()

    return SuccessResponse(
        data=LoginResponse(**user_data.__dict__, **token_data.__dict__),
        message=f"User {'created' if is_new_user else 'logged in'} successfully via OAuth",
    )
