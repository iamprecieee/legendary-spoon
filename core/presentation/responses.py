from typing import Any

from fastapi import status
from pydantic import BaseModel


class StandardResponse(BaseModel):
    """Base response model for all API operations.

    Provides a consistent structure for success, data, and optional metadata.

    Attributes:
        success: A boolean indicating if the API request was successful (default: True).
        data: The actual response data payload (can be any type, default: None).
    """

    success: bool = True
    data: Any = None


class SuccessResponse(StandardResponse):
    """Standard response model for successful API operations (HTTP 200 OK).

    Inherits `success` and `data` from `StandardResponse`.

    Attributes:
        message: A descriptive success message (default: "Resource action successful").
        status_code: The HTTP status code (default: 200 OK).
    """

    message: str = "Resource action successful"
    status_code: int = status.HTTP_200_OK


class CreatedResponse(StandardResponse):
    """Response model for successful resource creation (HTTP 201 Created).

    Inherits `success` and `data` from `StandardResponse`.

    Attributes:
        message: A descriptive success message (default: "Resource creation successful").
        status_code: The HTTP status code (default: 201 Created).
    """

    message: str = "Resource creation successful"
    status_code: int = status.HTTP_201_CREATED


class UpdatedResponse(StandardResponse):
    """Response model for successful resource update (HTTP 202 Accepted).

    Inherits `success` and `data` from `StandardResponse`.

    Attributes:
        message: A descriptive success message (default: "Resource update successful").
        status_code: The HTTP status code (default: 202 Accepted).
    """

    message: str = "Resource update successful"
    status_code: int = status.HTTP_202_ACCEPTED


class DeletedResponse(StandardResponse):
    """Response model for successful resource deletion (HTTP 204 No Content).

    Inherits `success` and `data` from `StandardResponse`.

    Attributes:
        message: A descriptive success message (default: "Resource deletion successful").
        status_code: The HTTP status code (default: 204 No Content).
    """

    message: str = "Resource deletion successful"
    status_code: int = status.HTTP_204_NO_CONTENT
