from typing import Any

from fastapi import status
from pydantic import BaseModel


class StandardResponse(BaseModel):
    success: bool = True
    data: Any = None


class SuccessResponse(StandardResponse):
    message: str = "Resource action successful"
    status_code: int = status.HTTP_200_OK


class CreatedResponse(StandardResponse):
    message: str = "Resource creation successful"
    status_code: int = status.HTTP_201_CREATED


class UpdatedResponse(StandardResponse):
    message: str = "Resource update successful"
    status_code: int = status.HTTP_202_ACCEPTED


class DeletedResponse(StandardResponse):
    message: str = "Resource deletion successful"
    status_code: int = status.HTTP_204_NO_CONTENT
