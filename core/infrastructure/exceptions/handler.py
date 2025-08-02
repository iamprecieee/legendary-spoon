import json
import traceback
from typing import Any, Dict, List

from fastapi import HTTPException, Request, status
from fastapi.exceptions import RequestValidationError, ResponseValidationError
from fastapi.responses import JSONResponse
from loguru import logger
from pydantic import ValidationError
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from starlette.exceptions import HTTPException as StarletteHTTPException

from ..factory import get_data_sanitizer


def normalize_error_detail(detail: Any) -> str | List[str] | Dict[str, Any]:
    """Normalizes the error detail to a string, list of strings, or dictionary for consistent API responses.

    This function processes various formats of error details (e.g., from Pydantic validation errors)
    and converts them into a standardized format suitable for API responses.

    Args:
        detail: The raw error detail, which can be a string, dictionary, or list.

    Returns:
        A normalized representation of the error detail: a string, a list of strings,
        or a dictionary, depending on the input type and content.
    """
    if isinstance(detail, str):
        return detail

    if isinstance(detail, dict):
        normalized = ""
        for key, value in detail.items():
            # If value is iterable (but not a string), handle as list
            if hasattr(value, "__iter__") and not isinstance(value, str):
                if len(value) == 1:
                    normalized = str(value[0])
                else:
                    normalized = [str(v) for v in value]
            else:
                normalized = str(value)
        return normalized

    if hasattr(detail, "__iter__") and not isinstance(detail, str):
        return [str(item) for item in detail]

    return str(detail)


async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Global exception handler for the FastAPI application.

    This handler catches various types of exceptions (e.g., ValueError, SQLAlchemyError,
    HTTPException, ValidationError) and returns a consistent JSON response format.
    It also sanitizes sensitive information before logging.

    Args:
        request: The incoming FastAPI request object.
        exc: The exception that was caught.

    Returns:
        A `JSONResponse` object with a standardized error format and appropriate HTTP status code.
    """
    exc_type = type(exc).__name__
    sanitizer = await get_data_sanitizer()

    if hasattr(exc, "statement") and hasattr(exc, "params"):
        exc_msg = sanitizer.sanitize_sql_for_logging(exc.statement, exc.params)
    elif hasattr(exc, "response"):
        exc_msg = sanitizer.sanitize_exception_for_logging(
            json.loads(exc.response.text)
        )
    else:
        exc_msg = sanitizer.sanitize_exception_for_logging(str(exc))

    custom_response_data = {
        "success": False,
        "message": "An error occurred",
        "errors": {},
        "status_code": None,
        "path": str(request.url),
        "method": request.method,
    }

    if isinstance(exc, ValueError):
        custom_response_data.update(
            {
                "message": "Invalid field items",
                "errors": {"detail": str(exc)},
                "status_code": status.HTTP_400_BAD_REQUEST,
            }
        )
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST, content=custom_response_data
        )

    if isinstance(exc, IntegrityError):
        custom_response_data.update(
            {
                "message": "Database constraint violation",
                "errors": {"detail": str(exc.orig)},
                "status_code": status.HTTP_409_CONFLICT,
            }
        )
        return JSONResponse(
            status_code=status.HTTP_409_CONFLICT, content=custom_response_data
        )

    if isinstance(exc, SQLAlchemyError):
        custom_response_data.update(
            {
                "message": "Database error occurred",
                "errors": {"detail": "A database error occurred"},
                "status_code": status.HTTP_500_INTERNAL_SERVER_ERROR,
            }
        )

        logger.error(f"📝 SQLAlchemyError -> {exc_type}: {exc_msg}")

        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content=custom_response_data,
        )

    if isinstance(
        exc, (ValidationError, RequestValidationError, ResponseValidationError)
    ):
        errors = {}
        for error in exc.errors():
            field = ".".join(str(x) for x in error["loc"])
            errors["detail"] = f"{error['msg']} in {field}"

        custom_response_data.update(
            {
                "message": "Validation error",
                "errors": errors,
                "status_code": status.HTTP_422_UNPROCESSABLE_ENTITY,
            }
        )
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content=custom_response_data,
        )

    if isinstance(exc, HTTPException):
        custom_response_data.update(
            {
                "status_code": exc.status_code,
                "errors": {"detail": normalize_error_detail(exc.detail)},
            }
        )

        if exc.status_code == status.HTTP_404_NOT_FOUND:
            custom_response_data["message"] = "Resource not found"
        elif exc.status_code == status.HTTP_401_UNAUTHORIZED:
            custom_response_data["message"] = "Authentication required"
        elif exc.status_code == status.HTTP_403_FORBIDDEN:
            custom_response_data["message"] = "Permission denied"
        elif exc.status_code == status.HTTP_400_BAD_REQUEST:
            custom_response_data["message"] = "Bad request"
        elif exc.status_code == status.HTTP_409_CONFLICT:
            custom_response_data["message"] = "Conflict occurred"
        elif exc.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY:
            custom_response_data["message"] = "Validation error"
        elif exc.status_code == status.HTTP_429_TOO_MANY_REQUESTS:
            custom_response_data["message"] = "Rate limit exceeded"
        elif exc.status_code >= 500:
            custom_response_data["message"] = "Internal server error"

        return JSONResponse(status_code=exc.status_code, content=custom_response_data)

    if isinstance(exc, StarletteHTTPException):
        custom_response_data.update(
            {
                "message": "HTTP error occurred",
                "errors": {"detail": str(exc.detail)},
                "status_code": exc.status_code,
            }
        )
        return JSONResponse(status_code=exc.status_code, content=custom_response_data)

    # For all other unhandled exceptions, log and return a generic 500 error
    tb = traceback.extract_tb(exc.__traceback__)
    if tb:
        last_frame = tb[-1]
        location = f'File "{last_frame.filename}", line {last_frame.lineno}, in {last_frame.name}'
    else:
        location = "No traceback available"

    logger.critical(
        f"☢️ Unhandled exception -> {exc_type}: {exc_msg}\nLocation: {location}"
    )

    custom_response_data.update(
        {
            "message": "Internal server error",
            "errors": {"detail": "An unexpected error occurred"},
            "status_code": status.HTTP_500_INTERNAL_SERVER_ERROR,
        }
    )

    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, content=custom_response_data
    )
