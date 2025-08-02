import contextvars
import uuid
from typing import Any, Dict

request_context: contextvars.ContextVar[Dict[str, Any]] = contextvars.ContextVar(
    "request_context", default={}
)
"""A `ContextVar` to store request-specific contextual data for logging.

This variable allows various parts of the application to contribute key-value pairs
that will be automatically included in log records associated with the current request.
"""


class RequestContextLogger:
    """Context manager for adding request-specific information to logs.

    This helps track operations that belong to the same request.
    """

    def __init__(self, request_id: str = None, **context):
        """Initializes the RequestContextLogger.

        Args:
            request_id: An optional unique identifier for the request.
                        If not provided, a short UUID is generated.
            **context: Additional key-value pairs to add to the request context.
        """
        self.request_id = request_id or str(uuid.uuid4())[:8]
        self.context = {"request_id": self.request_id, **context}
        self.token = None

    async def __aenter__(self):
        """Enters the asynchronous context, setting the request context.

        Returns:
            The instance of `RequestContextLogger`.
        """
        self.token = request_context.set(self.context)
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Exits the asynchronous context, resetting the request context.

        Args:
            exc_type: The type of the exception raised, if any.
            exc_val: The exception instance, if any.
            exc_tb: The traceback object, if any.
        """
        if self.token is not None:
            request_context.reset(self.token)
