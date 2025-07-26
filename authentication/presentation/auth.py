from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm

from core.presentation.responses import CreatedResponse, SuccessResponse
from users.infrastructure.factory import (
    get_current_user,
    get_user_repository,
    oauth2_scheme,
)

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
    get_google_oauth_service,
    get_jwt_token_service,
    get_password_service,
    get_refresh_token_repository,
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
    create_user_rule = CreateUserRule(
        email=request.email,
        password=request.password,
        user_repository=user_repository,
        password_service=password_service,
    )

    created_user = create_user_rule.execute()

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
    login_user_rule = LoginUserRule(
        email=request.email,
        password=request.password,
        user_repository=user_repository,
        password_service=password_service,
        token_service=token_service,
        refresh_token_repository=refresh_token_repository,
    )

    login_data = login_user_rule.execute()
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
):
    refresh_rule = RefreshTokenRule(
        refresh_token=request.refresh_token,
        user_repository=user_repository,
        token_service=token_service,
        refresh_token_repository=refresh_token_repository,
    )

    refresh_data = refresh_rule.execute()
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
    login_user_rule = LoginUserRule(
        email=form_data.username,
        password=form_data.password,
        user_repository=user_repository,
        password_service=password_service,
        token_service=token_service,
        refresh_token_repository=refresh_token_repository,
    )

    login_data = login_user_rule.execute()
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
    logout_rule = LogoutRule(
        access_token=access_token,
        refresh_token=request.refresh_token,
        token_service=token_service,
        blacklist_token_repository=blacklist_token_repository,
        refresh_token_repository=refresh_token_repository,
    )

    logout_rule.execute()

    return SuccessResponse(
        data={"message": "Logged out successfully"}, message="Logout successful"
    )


@router.get("/google/login", response_model=SuccessResponse, status_code=200)
async def google_login(
    oauth_service=Depends(get_google_oauth_service),
):
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
):
    oauth_callback_rule = OAuthCallbackRule(
        auth_code=code,
        oauth_service=oauth_service,
        user_repository=user_repository,
        token_service=token_service,
        refresh_token_repository=refresh_token_repository,
    )

    user_data, token_data, is_new_user = await oauth_callback_rule.execute()

    return SuccessResponse(
        data=LoginResponse(**user_data.__dict__, **token_data.__dict__),
        message=f"User {'created' if is_new_user else 'logged in'} successfully via OAuth",
    )
