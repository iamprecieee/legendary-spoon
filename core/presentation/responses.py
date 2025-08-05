from typing import Any

from fastapi import status
from pydantic import BaseModel


class StandardResponse(BaseModel):
    """Base response model for all API operations.

    Provides a consistent structure for success, data, and optional metadata.

    Attributes
    ----------
    success: bool, default=True
        Boolean indicating if API request was successful.
    data: Any, default=None
        Actual response data payload.
    """

    success: bool = True
    data: Any = None


class SuccessResponse(StandardResponse):
    """Standard response model for successful API operations (HTTP 200 OK).

    Inherits `success` and `data` from `StandardResponse`.

    Attributes
    ----------
    message: str, default="Resource action successful"
        Descriptive success message.
    status_code: int, default=200
        HTTP status code.
    """

    message: str = "Resource action successful"
    status_code: int = status.HTTP_200_OK


class CreatedResponse(StandardResponse):
    """Response model for successful resource creation (HTTP 201 Created).

    Inherits `success` and `data` from `StandardResponse`.

    Attributes
    ----------
    message: str, default="Resource creation successful"
        Descriptive success message.
    status_code: int, default=201
        HTTP status code.
    """

    message: str = "Resource creation successful"
    status_code: int = status.HTTP_201_CREATED


class UpdatedResponse(StandardResponse):
    """Response model for successful resource update (HTTP 202 Accepted).

    Inherits `success` and `data` from `StandardResponse`.

    Attributes
    ----------
    message: str, default="Resource update successful"
        Descriptive success message.
    status_code: int, default=202
        HTTP status code.
    """

    message: str = "Resource update successful"
    status_code: int = status.HTTP_202_ACCEPTED


class DeletedResponse(StandardResponse):
    """Response model for successful resource deletion (HTTP 204 No Content).

    Inherits `success` and `data` from `StandardResponse`.

    Attributes
    ----------
    message: str, default="Resource deletion successful"
        Descriptive success message.
    status_code: int, default=204
        HTTP status code.
    """

    message: str = "Resource deletion successful"
    status_code: int = status.HTTP_204_NO_CONTENT
