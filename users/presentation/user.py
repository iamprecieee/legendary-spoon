from fastapi import APIRouter, Depends

from core.presentation.responses import SuccessResponse

from ..infrastructure.factory import get_current_user
from .responses import UserResponse

router = APIRouter(prefix="/users")


@router.get("/me", response_model=SuccessResponse, status_code=200)
async def read_me(current_user=Depends(get_current_user)):
    return SuccessResponse(
        data=UserResponse(**current_user.__dict__), message="User fetch successful"
    )
