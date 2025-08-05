from fastapi import APIRouter, Depends

from authentication.infrastructure.factory import get_current_user
from core.presentation.responses import SuccessResponse

from .responses import UserResponse

router = APIRouter(prefix="/users")


@router.get("/me", response_model=SuccessResponse, status_code=200)
async def read_me(current_user=Depends(get_current_user)) -> SuccessResponse:
    """Retrieve details of the currently authenticated user.

    Relies on the `get_current_user` dependency for identifying users.

    Parameters
    ----------
    current_user
        Dependency-injected `DomainUser` entity of the authenticated user.

    Returns
    -------
    SuccessResponse
        `SuccessResponse` containing the `UserResponse` data of the current user.
    """
    return SuccessResponse(
        data=UserResponse(**current_user.__dict__), message="User fetch successful"
    )
