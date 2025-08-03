import pickle
import re
from typing import Any, Dict, List, Pattern
from urllib.parse import urlparse, urlunparse

import msgpack
from redis.asyncio import Redis

from config.base import Settings

from ..application.ports import CacheServiceInterface


class DataSanitizer:
    """Comprehensive data sanitizer for removing/masking sensitive information
    from logs, exceptions, and other outputs.

    This class defines a set of patterns and methods to identify and mask
    sensitive data like passwords, tokens, API keys, and email addresses
    before they are logged or exposed.
    """

    def __init__(self):
        """Initializes the DataSanitizer with predefined sensitive patterns and regexes."""
        self.sensitive_patterns: List[Pattern[str]] = [
            re.compile(r"password", re.IGNORECASE),
            re.compile(r"passwd", re.IGNORECASE),
            re.compile(r"secret", re.IGNORECASE),
            re.compile(r"token", re.IGNORECASE),
            re.compile(r"key", re.IGNORECASE),
            re.compile(r"auth", re.IGNORECASE),
            re.compile(r"credential", re.IGNORECASE),
            re.compile(r"api", re.IGNORECASE),
            re.compile(r"api_key", re.IGNORECASE),
            re.compile(r"code", re.IGNORECASE),
            re.compile(r"state", re.IGNORECASE),
            re.compile(r"session", re.IGNORECASE),
            re.compile(r"csrf", re.IGNORECASE),
            re.compile(r"social_id", re.IGNORECASE),
        ]

        self.email_pattern = re.compile(
            r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        )
        self.url_with_params_pattern = re.compile(
            r"(?:https?://[^\s]+\?[^\s]+|[^\s]*\?[^\s&=]+=[^\s&=]+(?:&[^\s&=]+=[^\s&=]+)*)"
        )
        self.query_params_pattern = re.compile(
            r"(?:^|\s)([a-zA-Z_][a-zA-Z0-9_]*=[^&\s]+(?:&[a-zA-Z_][a-zA-Z0-9_]*=[^&\s]+)*)(?:\s|$)"
        )

    def sanitize_for_logging(self, data: Any) -> Any:
        """Sanitizes data for logging purposes.

        Recursively processes input data (strings, dicts, lists) to mask
        sensitive information based on predefined patterns.

        Args:
            data: The data to be sanitized (can be string, dict, list, etc.).

        Returns:
            The sanitized data with sensitive information masked.
        """
        return self._sanitize_value(data)

    def sanitize_sql_for_logging(self, sql: str, params: Any) -> tuple[str, Any]:
        """Sanitizes SQL statements and their parameters for logging.

        Identifies sensitive fields in SQL parameters and masks their values.

        Args:
            sql: The SQL query string.
            params: The parameters associated with the SQL query (can be a list or dict).

        Returns:
            A tuple containing the original SQL string and the sanitized parameters.
        """
        return self._sanitize_sql_params(sql, params)

    def sanitize_exception_for_logging(self, exception: Exception) -> Exception:
        """Sanitizes exception arguments for logging.

        Attempts to mask sensitive information within the arguments of an exception.
        If sanitization fails, returns a generic sanitized exception message.

        Args:
            exception: The exception object to sanitize.

        Returns:
            A sanitized version of the exception, or a generic Exception if sanitization fails.
        """
        try:
            try:
                sanitized_args = self._sanitize_exception_args(exception.args)
            except Exception:
                sanitized_args = self._sanitize_exception_args(exception)
            return sanitized_args
        except Exception:
            return Exception(f"***SANITIZED*** {type(exception).__name__}")

    def _is_sensitive_field(self, field_name: str) -> bool:
        """Checks if a given field name is considered sensitive.

        Args:
            field_name: The name of the field to check.

        Returns:
            True if the field name matches any sensitive pattern, False otherwise.
        """
        return any(pattern.search(field_name) for pattern in self.sensitive_patterns)

    def _mask_email(self, email: str) -> str:
        """Masks an email address for privacy.

        Reveals the first and last character of the local part and the full domain.

        Args:
            email: The email string to mask.

        Returns:
            The masked email string (e.g., e****l@example.com).
        """
        if "@" in email:
            local, domain = email.split("@", 1)
            if len(local) <= 2:
                masked_local = "*" * len(local)
            else:
                masked_local = local[0] + "*" * (len(local) - 2) + local[-1]
            return f"{masked_local}@{domain}"
        return "***@***.***"

    def _sanitize_query_params(self, query_string: str) -> str:
        """Sanitizes query parameters in a URL string.

        Identifies and masks sensitive query parameter values.

        Args:
            query_string: The URL query string (e.g., "param1=val1&param2=val2").

        Returns:
            The query string with sensitive parameter values masked.
        """
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
        """Sanitizes query parameters within a full URL string.

        Parses the URL, sanitizes its query components, and reconstructs the URL.

        Args:
            url: The full URL string to sanitize.

        Returns:
            The URL string with sensitive query parameters masked.
        """
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
        """Sanitizes a string by masking sensitive patterns, emails, and URLs.

        Also truncates the string if it exceeds `max_length`.

        Args:
            text: The string to sanitize.
            max_length: The maximum length of the sanitized string.

        Returns:
            The sanitized and potentially truncated string.
        """
        if not isinstance(text, str):
            text = str(text)

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
        """Recursively sanitizes sensitive fields within a dictionary.

        Args:
            data: The dictionary to sanitize.
            max_depth: The maximum recursion depth to prevent infinite loops (default: 5).

        Returns:
            A new dictionary with sensitive values masked.
        """
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
        """Recursively sanitizes sensitive values within a list.

        Args:
            data: The list to sanitize.
            max_depth: The maximum recursion depth (default: 5).

        Returns:
            A new list with sensitive values masked. Limits processing to first 10 items.
        """
        if max_depth <= 0:
            return ["<max_depth_reached>"]

        return [self._sanitize_value(item, max_depth - 1) for item in data[:10]]

    def _sanitize_value(self, value: Any, max_depth: int = 5) -> Any:
        """Determines the appropriate sanitization method based on the value type.

        Args:
            value: The value to sanitize.
            max_depth: The current recursion depth limit.

        Returns:
            The sanitized value.
        """
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
        """Sanitizes SQL query parameters.

        Checks for sensitive patterns in parameter values and masks them.
        Specifically targets hashed passwords and long strings if sensitive fields are detected in SQL.

        Args:
            sql: The SQL query string.
            params: The parameters associated with the SQL query.

        Returns:
            A tuple containing the original SQL string and the sanitized parameters.
        """
        sanitized_sql = sql

        has_sensitive_fields = any(
            pattern.search(sql) for pattern in self.sensitive_patterns
        )

        if isinstance(params, (list, tuple)):
            sanitized_params = []
            for param in params:
                should_mask = False

                if isinstance(param, str):
                    if "$2b$" in param or "$argon2" in param or len(param) > 36:
                        # Likely a hashed password or a very long string that could be sensitive
                        should_mask = True
                    elif has_sensitive_fields and len(str(param)) > 5:
                        # If the SQL query itself contains sensitive keywords, mask longer string parameters
                        should_mask = True

                if should_mask:
                    sanitized_params.append("***MASKED***")
                else:
                    sanitized_params.append(self._sanitize_value(param))
            return sanitized_sql, sanitized_params
        elif isinstance(params, dict):
            return sanitized_sql, self._sanitize_dict(params)
        else:
            return sanitized_sql, self._sanitize_value(params)

    def _sanitize_exception_args(self, exc_args: tuple | Dict[str, Any]) -> tuple:
        """Sanitizes arguments of an exception.

        Looks for SQL parameters within exception messages and masks them.
        Recursively sanitizes other data structures within exception arguments.

        Args:
            exc_args: The arguments of the exception (can be a tuple or dictionary).

        Returns:
            A tuple of sanitized exception arguments.
        """
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
        elif isinstance(exc_args, str):
            sanitized_args.append(self._sanitize_string(exc_args))

        return tuple(sanitized_args)


class RedisCacheService(CacheServiceInterface):
    """Concrete implementation of `CacheServiceInterface` using Redis as the caching backend.

    This service provides methods for storing, retrieving, and deleting data from Redis,
    handling serialization and deserialization of Python objects.
    """

    def __init__(self, settings: Settings):
        """Initializes the RedisCacheService.

        Establishes connection parameters for Redis.

        Args:
            settings: Application settings, providing Redis host, port, DB, password,
                      and timeout configurations.
        """
        self._settings = settings
        self._redis: Redis | None = None

    async def _get_redis(self) -> Redis:
        """Establishes and returns an asynchronous Redis client instance.

        Ensures a single Redis client instance is used across the application
        (singleton pattern for the client).

        Returns:
            An asynchronous Redis client instance.
        """
        if self._redis is None:
            self._redis = Redis(
                host=self._settings.redis_host,
                port=self._settings.redis_port,
                db=self._settings.redis_db,
                password=self._settings.redis_password,
                decode_responses=False,
                socket_connect_timeout=self._settings.redis_socket_connect_timeout,
                socket_timeout=self._settings.redis_socket_timeout,
                retry_on_timeout=True,
                health_check_interval=30,
                ssl_cert_reqs=self._settings.ssl_cert_reqs,
                ssl=self._settings.redis_use_ssl,
            )

        return self._redis

    async def get(self, key: str) -> Any:
        """Retrieves a value from Redis by its key.

        Args:
            key: The key of the item to retrieve.

        Returns:
            The deserialized cached value, or None if the key does not exist.
        """
        try:
            redis_client = await self._get_redis()
            data = await redis_client.get(key)
            if data is None:
                return None

            return self._deserialize_data(data)

        except Exception as e:
            raise e

    async def set(self, key: str, value: Any, timeout: int | None = None) -> bool:
        """Sets a key-value pair in Redis with an optional expiration timeout.

        Args:
            key: The key for the item.
            value: The value to be cached.
            timeout: The expiration time in seconds. If None, uses the default cache timeout from settings.

        Returns:
            True if the operation was successful, False otherwise.
        """
        try:
            redis_client = await self._get_redis()
            serialized_value = self._serialize_value(value)
            timeout = timeout or self._settings.cache_timeout_seconds
            if timeout is not None:
                result = await redis_client.setex(key, timeout, serialized_value)
            else:
                result = await redis_client.set(key, serialized_value)

            return bool(result)

        except Exception as e:
            raise e

    async def delete(self, key: str) -> bool:
        """Deletes a key-value pair from Redis.

        Args:
            key: The key of the item to delete.

        Returns:
            True if the item was successfully deleted, False otherwise.
        """
        try:
            redis_client = await self._get_redis()
            result = await redis_client.delete(key)
            return result > 0

        except Exception as e:
            raise e

    async def close(self) -> None:
        """Closes the Redis connection.

        Returns:
            True if the item was successfully deleted, False otherwise.
        """
        if self._redis:
            await self._redis.aclose()

            if hasattr(self._redis, "connection_pool"):
                await self._redis.connection_pool.disconnect()

            self._redis = None

    def _serialize_value(self, value: Any) -> bytes:
        """Serializes a Python object into bytes for storage in Redis.

        Attempts to use `msgpack` first, then falls back to `pickle` for complex types.

        Args:
            value: The Python object to serialize.

        Returns:
            The serialized object as bytes.
        """
        try:
            return msgpack.packb(value, use_bin_type=True)

        except (ValueError, TypeError):
            return pickle.dumps(value)

    def _deserialize_data(self, data: bytes) -> Any:
        """Deserializes bytes retrieved from Redis back into a Python object.

        Attempts to use `msgpack` first, then falls back to `pickle`.

        Args:
            data: The bytes retrieved from Redis.

        Returns:
            The deserialized Python object.
        """
        try:
            return msgpack.unpackb(data, raw=False)

        except (msgpack.exceptions.ExtraData, ValueError, TypeError):
            return pickle.loads(data)
