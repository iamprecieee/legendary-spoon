import traceback
from typing import Any, Dict, List

from fastapi import HTTPException, Request, status
from fastapi.exceptions import RequestValidationError, ResponseValidationError
from fastapi.responses import JSONResponse
from loguru import logger
from pydantic import ValidationError
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from starlette.exceptions import HTTPException as StarletteHTTPException


def normalize_error_detail(detail: Any) -> str | List[str] | Dict[str, Any]:
    """Normalize the error detail to a string, list of strings, or dict for consistent API responses."""

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
    custom_response_data = {
        "success": False,
        "message": "An error occurred",
        "errors": {},
        "status_code": None,
        "path": str(request.url),
        "method": request.method,
    }

    # Handle database integrity errors (e.g., unique constraint violations)
    if isinstance(exc, IntegrityError):
        custom_response_data.update(
            {
                "message": "Database constraint violation",
                "errors": {
                    "detail": f"Database constraint violation occurred: {str(exc.orig)}"
                },
                "status_code": status.HTTP_409_CONFLICT,
            }
        )
        return JSONResponse(
            status_code=status.HTTP_409_CONFLICT, content=custom_response_data
        )

    # Handle Pydantic validation errors
    if isinstance(exc, ValidationError):
        errors = {}
        for error in exc.errors():
            field = ".".join(str(x) for x in error["loc"])
            errors[field] = error["msg"]

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

    # Handle FastAPI request validation errors
    if isinstance(exc, RequestValidationError):
        errors = {}
        for error in exc.errors():
            field = ".".join(str(x) for x in error["loc"])
            errors[field] = error["msg"]

        custom_response_data.update(
            {
                "message": "Request validation error",
                "errors": errors,
                "status_code": status.HTTP_422_UNPROCESSABLE_ENTITY,
            }
        )
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content=custom_response_data,
        )

    # Handle FastAPI response validation errors
    if isinstance(exc, ResponseValidationError):
        errors = {}
        for error in exc.errors():
            field = ".".join(str(x) for x in error["loc"])
            errors[field] = error["msg"]

        custom_response_data.update(
            {
                "message": "Response validation error",
                "errors": errors,
                "status_code": status.HTTP_422_UNPROCESSABLE_ENTITY,
            }
        )
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content=custom_response_data,
        )

    # Handle generic value errors
    if isinstance(exc, ValueError):
        custom_response_data.update(
            {
                "message": "Invalid value provided",
                "errors": {"detail": str(exc)},
                "status_code": status.HTTP_400_BAD_REQUEST,
            }
        )
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST, content=custom_response_data
        )

    # Handle FastAPI HTTPException (e.g., 404, 401, etc.)
    if isinstance(exc, HTTPException):
        custom_response_data.update(
            {
                "status_code": exc.status_code,
                "errors": {"detail": normalize_error_detail(exc.detail)},
            }
        )

        # Set a more specific message based on status code
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

    # Handle Starlette HTTPException (should rarely occur separately)
    if isinstance(exc, StarletteHTTPException):
        custom_response_data.update(
            {
                "message": "HTTP error occurred",
                "errors": {"detail": str(exc.detail)},
                "status_code": exc.status_code,
            }
        )
        return JSONResponse(status_code=exc.status_code, content=custom_response_data)

    # Handle generic SQLAlchemy errors
    if isinstance(exc, SQLAlchemyError):
        custom_response_data.update(
            {
                "message": "Database error occurred",
                "errors": {"detail": "A database error occurred"},
                "status_code": status.HTTP_500_INTERNAL_SERVER_ERROR,
            }
        )
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content=custom_response_data,
        )

    # For all other unhandled exceptions, log and return a generic 500 error
    tb = traceback.extract_tb(exc.__traceback__)
    if tb:
        last_frame = tb[-1]
        location = f'File "{last_frame.filename}", line {last_frame.lineno}, in {last_frame.name}'
    else:
        location = "No traceback available"

    exc_type = type(exc).__name__
    exc_msg = str(exc)

    logger.error(
        f"Unhandled exception -> {exc_type}: {exc_msg}\nLocation: {location}",
        exc_info=exc,
        extra={
            "request_method": request.method,
            "request_url": str(request.url),
            "exception_type": exc_type,
        },
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
