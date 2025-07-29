import contextvars
import uuid
from typing import Any, Dict

request_context: contextvars.ContextVar[Dict[str, Any]] = contextvars.ContextVar(
    "request_context", default={}
)


class RequestContextLogger:
    """
    Context manager for adding request-specific information to logs.

    This helps track operations that belong to the same request.
    """

    def __init__(self, request_id: str = None, **context):
        self.request_id = request_id or str(uuid.uuid4())[:8]
        self.context = {"request_id": self.request_id, **context}

    def __enter__(self):
        request_context.set(self.context)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        request_context.set({})
