import re
from typing import Any, Dict, List, Pattern
from urllib.parse import urlparse, urlunparse


class DataSanitizer:
    """
    Comprehensive data sanitizer for removing/masking sensitive information
    from logs, exceptions, and other outputs.
    """

    def __init__(self):
        self.sensitive_patterns: List[Pattern[str]] = [
            re.compile(r"password", re.IGNORECASE),
            re.compile(r"passwd", re.IGNORECASE),
            re.compile(r"secret", re.IGNORECASE),
            re.compile(r"token", re.IGNORECASE),
            re.compile(r"key", re.IGNORECASE),
            re.compile(r"auth", re.IGNORECASE),
            re.compile(r"credential", re.IGNORECASE),
            re.compile(r"api.key", re.IGNORECASE),
            re.compile(r"code", re.IGNORECASE),
            re.compile(r"state", re.IGNORECASE),
            re.compile(r"session", re.IGNORECASE),
            re.compile(r"csrf", re.IGNORECASE),
            re.compile(r"social_id", re.IGNORECASE),
        ]

        self.email_pattern = re.compile(r"^[a-zA-Z]+[\w\.-]+@[\w\.-]+\.[a-z\.]+")

        self.url_with_params_pattern = re.compile(
            r"(?:https?://[^\s]+\?[^\s]+|[^\s]*\?[^\s&=]+=[^\s&=]+(?:&[^\s&=]+=[^\s&=]+)*)"
        )

        self.query_params_pattern = re.compile(
            r"(?:^|\s)([a-zA-Z_][a-zA-Z0-9_]*=[^&\s]+(?:&[a-zA-Z_][a-zA-Z0-9_]*=[^&\s]+)*)(?:\s|$)"
        )

    def sanitize_for_logging(self, data: Any) -> Any:
        return self._sanitize_value(data)

    def sanitize_sql_for_logging(self, sql: str, params: Any) -> tuple[str, Any]:
        return self._sanitize_sql_params(sql, params)

    def sanitize_exception_for_logging(self, exception: Exception) -> Exception:
        try:
            try:
                sanitized_args = self._sanitize_exception_args(exception.args)
            except Exception:
                sanitized_args = self._sanitize_exception_args(exception)
            return sanitized_args
        except Exception:
            return Exception(f"***SANITIZED*** {type(exception).__name__}")

    def _is_sensitive_field(self, field_name: str) -> bool:
        return any(pattern.search(field_name) for pattern in self.sensitive_patterns)

    def _mask_email(self, email: str) -> str:
        if "@" in email:
            local, domain = email.split("@", 1)
            if len(local) <= 2:
                masked_local = "*" * len(local)
            else:
                masked_local = local[0] + "*" * (len(local) - 2) + local[-1]
            return f"{masked_local}@{domain}"
        return "***@***.***"

    def _sanitize_query_params(self, query_string: str) -> str:
        try:
            params = {}
            for param_pair in query_string.split("&"):
                if "=" in param_pair:
                    key, value = param_pair.split("=", 1)
                    params[key] = value
                else:
                    params[param_pair] = ""

            sanitized_params = {}
            for key, value in params.items():
                if self._is_sensitive_field(key):
                    sanitized_params[key] = "***MASKED***"
                else:
                    sanitized_params[key] = value

            return "&".join([f"{k}={v}" for k, v in sanitized_params.items()])
        except Exception:
            return "***SANITIZED_PARAMS***"

    def _sanitize_url_with_params(self, url: str) -> str:
        try:
            parsed = urlparse(url)
            if parsed.query:
                sanitized_query = self._sanitize_query_params(parsed.query)
                # Reconstruct URL with sanitized query
                return urlunparse(
                    (
                        parsed.scheme,
                        parsed.netloc,
                        parsed.path,
                        parsed.params,
                        sanitized_query,
                        parsed.fragment,
                    )
                )
            return url
        except Exception:
            return "***SANITIZED_URL***"

    def _sanitize_string(self, text: str, max_length: int = 1000) -> str:
        if not isinstance(text, str):
            text = str(text)

        # Truncate if too long
        if len(text) > max_length:
            text = text[:max_length] + "..."

        text = self.email_pattern.sub(lambda m: self._mask_email(m.group()), text)
        text = self.url_with_params_pattern.sub(
            lambda m: self._sanitize_url_with_params(m.group()), text
        )

        def sanitize_query_match(match):
            query_string = match.group(1)
            return match.group(0).replace(
                query_string, self._sanitize_query_params(query_string)
            )

        text = self.query_params_pattern.sub(sanitize_query_match, text)

        return text

    def _sanitize_dict(
        self, data: Dict[str, Any], max_depth: int = 5
    ) -> Dict[str, Any]:
        if max_depth <= 0:
            return {"<max_depth_reached>": "..."}

        sanitized = {}
        for key, value in data.items():
            if self._is_sensitive_field(key):
                sanitized[key] = "***MASKED***"
            else:
                sanitized[key] = self._sanitize_value(value, max_depth - 1)

        return sanitized

    def _sanitize_list(self, data: List[Any], max_depth: int = 5) -> List[Any]:
        if max_depth <= 0:
            return ["<max_depth_reached>"]

        return [self._sanitize_value(item, max_depth - 1) for item in data[:10]]

    def _sanitize_value(self, value: Any, max_depth: int = 5) -> Any:
        if value is None:
            return None

        if isinstance(value, dict):
            return self._sanitize_dict(value, max_depth)
        elif isinstance(value, (list, tuple)):
            return self._sanitize_list(list(value), max_depth)
        elif isinstance(value, (int, float, bool)):
            return value
        else:
            return self._sanitize_string(str(value))

    def _sanitize_sql_params(self, sql: str, params: Any) -> tuple[str, Any]:
        # Keep SQL query as-is (it shouldn't contain sensitive data)
        sanitized_sql = sql

        has_sensitive_fields = any(
            pattern.search(sql) for pattern in self.sensitive_patterns
        )

        if isinstance(params, (list, tuple)):
            sanitized_params = []
            for param in params:
                should_mask = False

                if isinstance(param, str):
                    # Check for obvious hashes/tokens
                    if "$2b$" in param or "$argon2" in param or len(param) > 50:
                        should_mask = True
                    # If SQL contains sensitive fields, mask string parameters
                    elif has_sensitive_fields and len(str(param)) > 5:
                        should_mask = True

                if should_mask:
                    sanitized_params.append("***MASKED***")
                else:
                    sanitized_params.append(self._sanitize_value(param))
            return sanitized_sql, sanitized_params
        elif isinstance(params, dict):
            # For named parameters
            return sanitized_sql, self._sanitize_dict(params)
        else:
            return sanitized_sql, self._sanitize_value(params)

    def _sanitize_exception_args(self, exc_args: tuple | Dict[str, Any]) -> tuple:
        sanitized_args = []
        if isinstance(exc_args, tuple):
            for arg in exc_args:
                if isinstance(arg, str):
                    if "[parameters:" in arg:
                        arg = re.sub(
                            r"\[parameters: \([^)]+\)\]",
                            "[parameters: ***SANITIZED***]",
                            arg,
                        )
                    sanitized_args.append(self._sanitize_string(arg))
                else:
                    sanitized_args.append(self._sanitize_value(arg))
        elif isinstance(exc_args, dict):
            sanitized_args.append(
                [
                    f"{key}={value}"
                    for key, value in self._sanitize_dict(exc_args).items()
                ]
            )

        return tuple(sanitized_args)
