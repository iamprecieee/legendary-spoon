import contextvars
import uuid
from typing import Any, Dict

request_context: contextvars.ContextVar[Dict[str, Any]] = contextvars.ContextVar(
    "request_context", default={}
)


class RequestContextLogger:
    """Context manager for adding request-specific information to logs.

    Helps track operations that belong to the same request.
    """

    def __init__(self, request_id: str = None, **context):
        self.request_id = request_id or str(uuid.uuid4())[:8]
        self.context = {"request_id": self.request_id, **context}
        self.token = None

    async def __aenter__(self):
        """Enter the asynchronous context, set the request context.

        Returns
        -------
        RequestContextLogger
            Instance of `RequestContextLogger`.
        """
        self.token = request_context.set(self.context)
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Exit the asynchronous context, reset the request context."""
        if self.token is not None:
            request_context.reset(self.token)
