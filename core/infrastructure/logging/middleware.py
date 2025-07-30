import json
import uuid
from typing import Callable

from fastapi import Request, Response
from loguru import logger
from starlette.middleware.base import BaseHTTPMiddleware

from ..factory import get_data_sanitizer
from .context import RequestContextLogger


class RequestTrackingMiddleware(BaseHTTPMiddleware):
    """
    Comprehensive request tracking middleware that adds logging
    and context to every API request. This middleware:

    1. Generates unique request IDs for tracing
    2. Logs request/response information
    3. Handles errors gracefully with context
    """

    def __init__(
        self,
        app,
        include_request_body: bool = False,
        include_response_body: bool = False,
    ):
        super().__init__(app)
        self.include_request_body = include_request_body
        self.include_response_body = include_response_body

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        request_id = str(uuid.uuid4())[:8]
        client_ip = self._get_client_ip(request)
        user_agent = request.headers.get("user-agent", "Unknown")

        sanitizer = await get_data_sanitizer()

        request_context = {
            "client_ip": client_ip,
            "user_agent": user_agent[:100],
            "method": request.method,
            "path": str(request.url.path),
            "query_params": str(request.url.query) if request.url.query else None,
        }

        safe_headers = self._get_safe_headers(request.headers)
        if safe_headers:
            request_context.update(
                {"headers": [f"{k}={v}" for k, v in safe_headers.items()]}
            )

        with RequestContextLogger(request_id=request_id, **request_context):
            logger.info(
                sanitizer.sanitize_for_logging(
                    f"🔄 Incoming {request.method} request to {request.url.path} 🔄"
                )
            )

            if request.url.query:
                logger.debug(
                    sanitizer.sanitize_for_logging(
                        f"🔍 Query parameters: {request.url.query} 🔍"
                    )
                )

            try:
                response = await call_next(request)
                return response

            except Exception as e:
                logger.error(
                    sanitizer.sanitize_exception_for_logging(
                        f"💥 Request failed: {type(e).__name__}: {str(e)}"
                    )
                )
                raise

    def _get_client_ip(self, request: Request) -> str:
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()

        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip

        if request.client:
            return request.client.host

        return "unknown"

    def _get_safe_headers(self, headers) -> dict:
        sensitive_headers = {
            "authorization",
            "cookie",
            "x-api-key",
            "x-auth-token",
            "x-csrf-token",
            "x-forwarded-for",
            "x-real-ip",
        }

        safe_headers = {}
        for name, value in headers.items():
            if name.lower() not in sensitive_headers:
                safe_headers[name] = value

        return safe_headers

    async def _get_request_body(self, request: Request) -> str:
        try:
            content_type = request.headers.get("content-type", "")

            if any(
                ct in content_type.lower() for ct in ["json", "text", "xml", "form"]
            ):
                body = await request.body()
                if body:
                    text_body = body.decode("utf-8", errors="ignore")

                    if "json" in content_type.lower():
                        try:
                            parsed_data = json.loads(text_body)
                            return json.dumps(parsed_data, indent=2)
                        except json.JSONDecodeError:
                            return text_body

                    return text_body
        except Exception:
            pass

        return None
