import hashlib
import pickle
import re
from typing import Any, Dict, List, Pattern, Tuple
from urllib.parse import urlparse, urlunparse

import msgpack
from redis.asyncio import Redis

from config.base import Settings

from ..application.ports import CacheServiceInterface


class DataSanitizer:
    """Comprehensive data sanitizer for removing/masking sensitive information
    from logs, exceptions, and other outputs.

    Defines a set of patterns and methods to identify and mask
    sensitive data like passwords, tokens, API keys, and email addresses
    before they are logged or exposed.
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
        """Sanitize data for logging purposes.

        Recursively processes input data (strings, dicts, lists) to mask
        sensitive information based on predefined patterns.

        Parameters
        ----------
        data: Any
            Data to be sanitized (can be string, dict, list, etc.).

        Returns
        -------
        Any
            Sanitized data with sensitive information masked.
        """
        return self._sanitize_value(data)

    def sanitize_sql_for_logging(self, sql: str, params: Any) -> Tuple[str, Any]:
        """Sanitize SQL statements and their parameters for logging.

        Identifies sensitive fields in SQL parameters and masks their values.

        Parameters
        ----------
        sql: str
            SQL query string.
        params: Any
            Parameters associated with the SQL query (can be a list or dict).

        Returns
        -------
        Tuple[str, Any]
            Tuple containing the original SQL string and the sanitized parameters.
        """
        return self._sanitize_sql_params(sql, params)

    def sanitize_exception_for_logging(self, exception: Exception) -> Exception:
        """Sanitize exception arguments for logging.

        Attempts to mask sensitive information within the arguments of an exception.
        If sanitization fails, returns a generic sanitized exception message.

        Parameters
        ----------
        exception: Exception
            Exception object to sanitize.

        Returns
        -------
        Exception
            Sanitized version of the exception, or a generic Exception if sanitization fails.
        """
        try:
            try:
                sanitized_args = self._sanitize_exception_args(exception.args)
                if sanitized_args == ():
                    raise
            except Exception:
                sanitized_args = self._sanitize_exception_args(exception)
            return sanitized_args
        except Exception:
            return Exception(f"***SANITIZED*** {type(exception).__name__}")

    def _is_sensitive_field(self, field_name: str) -> bool:
        """Check if a given field name is considered sensitive.

        Parameters
        ----------
        field_name: str
            Name of the field to check.

        Returns
        -------
        bool
            True if the field name matches any sensitive pattern, False otherwise.
        """
        return any(pattern.search(field_name) for pattern in self.sensitive_patterns)

    def _mask_email(self, email: str) -> str:
        """Mask an email address for privacy.

        Reveals the first and last character of the local part and the full domain.

        Parameters
        ----------
        email: str
            Email string to mask.

        Returns
        -------
        str
            Masked email string (e.g., e****l@example.com).
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
        """Sanitize query parameters in a URL string.

        Identifies and masks sensitive query parameter values.

        Parameters
        ----------
        query_string: str
            URL query string (e.g., "param1=val1&param2=val2").

        Returns
        -------
        str
            Query string with sensitive parameter values masked.
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
        """Sanitize query parameters within a full URL string.

        Parses the URL, sanitizes its query components, and reconstructs the URL.

        Parameters
        ----------
        url: str
            Full URL string to sanitize.

        Returns
        -------
        str
            URL string with sensitive query parameters masked.
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
        """Sanitize a string by masking sensitive patterns, emails, and URLs.

        Also truncates the string if it exceeds `max_length`.

        Parameters
        ----------
        text: str
            String to sanitize.
        max_length: int, default=1000
            Maximum length of the sanitized string.

        Returns
        -------
        str
            Sanitized and potentially truncated string.
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
        """Recursively sanitize sensitive fields within a dictionary.

        Parameters
        ----------
        data: Dict[str, Any]
            Dictionary to sanitize.
        max_depth: int, default=5
            Maximum recursion depth to prevent infinite loops.

        Returns
        -------
        Dict[str, Any]
            New dictionary with sensitive values masked.
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
        """Recursively sanitize sensitive values within a list.

        Parameters
        ----------
        data: List[Any]
            List to sanitize.
        max_depth: int, default=5
            Maximum recursion depth.

        Returns
        -------
        List[Any]
            New list with sensitive values masked. Limits processing to first 10 items.
        """
        if max_depth <= 0:
            return ["<max_depth_reached>"]

        return [self._sanitize_value(item, max_depth - 1) for item in data[:10]]

    def _sanitize_value(self, value: Any, max_depth: int = 5) -> Any:
        """Determine the appropriate sanitization method based on the value type.

        Parameters
        ----------
        value: Any
            Value to sanitize.
        max_depth: int, default=5
            Current recursion depth limit.

        Returns
        -------
        Any
            Sanitized value.
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
        """Sanitize SQL query parameters.

        Checks for sensitive patterns in parameter values and masks them.
        Specifically targets hashed passwords and long strings if sensitive fields are detected in SQL.

        Parameters
        ----------
        sql: str
            SQL query string.
        params: Any
            Parameters associated with the SQL query.

        Returns
        -------
        tuple[str, Any]
            Tuple containing the original SQL string and the sanitized parameters.
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
                        should_mask = True
                    elif has_sensitive_fields and len(str(param)) > 5:
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

    def _sanitize_exception_args(self, exc_args: str | tuple | Dict[str, Any]) -> tuple:
        """Sanitize arguments of an exception.

        Looks for SQL parameters within exception messages and masks them.
        Recursively sanitizes other data structures within exception arguments.

        Parameters
        ----------
        exc_args: tuple | Dict[str, Any]
            Arguments of the exception (can be a tuple or dictionary).

        Returns
        -------
        tuple
            Tuple of sanitized exception arguments.
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
        else:
            sanitized_args.append(self._sanitize_value(str(exc_args)))

        return tuple(sanitized_args)


class RedisCacheService(CacheServiceInterface):
    """Concrete implementation of `CacheServiceInterface` using Redis as the caching backend.

    Provides methods for storing, retrieving, and deleting data from Redis,
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
        """Establish and return an asynchronous Redis client instance.

        Ensures a single Redis client instance is used across the application
        (singleton pattern for the client).

        Returns
        -------
        Redis
            Asynchronous Redis client instance.
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
                max_connections=10,
            )

        return self._redis

    @staticmethod
    def get_cache_key(key_prefix: str, func_name: str, *args, **kwargs) -> str:
        """Generate a unique cache key based on function arguments.

        Creates a consistent and unique string representation
        of the arguments passed to a cached function, which is then hashed.

        Parameters
        ----------
        key_prefix: str
            String value to identify the key.
        func_name: str
            Name of function/method being cached.
        *args
            Positional arguments passed to the function.
        **kwargs
            Keyword arguments passed to the function.

        Returns
        -------
        str
            String concat of a hexadecimal MD5 hash string, prefix, and func_name representing the unique cache key.
        """
        key_parts = []

        for i, arg in enumerate(args):
            if i == 0 and hasattr(arg, "__dict__") and hasattr(arg, "__class__"):
                continue

            key_parts.append(f"arg{i}:{str(arg)}")

        for key, value in sorted(kwargs.items()):
            key_parts.append(f"{key}:{str(value)}")

        key_string = "|".join(key_parts)
        key_suffix = hashlib.md5(key_string.encode()).hexdigest()

        return (
            f"{key_prefix}:{func_name}:{key_suffix}"
            if key_prefix
            else f"{func_name}:{key_suffix}"
        )

    async def get(self, key: str) -> Any:
        """Retrieve a value from Redis by its key.

        Parameters
        ----------
        key: str
            Key of the item to retrieve.

        Returns
        -------
        Any
            Deserialized cached value, or None if key does not exist.
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
        """Set a key-value pair in Redis with an optional expiration timeout.

        Parameters
        ----------
        key: str
            Key for the item.
        value: Any
            Value to be cached.
        timeout: int | None, optional
            Expiration time in seconds. If None, use the default cache timeout from settings.

        Returns
        -------
        bool

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
        """Delete a key-value pair from Redis.

        Parameters
        ----------
        key: str
            Key of the item to delete.

        Returns
        -------
        bool

        """
        try:
            redis_client = await self._get_redis()
            result = await redis_client.delete(key)
            return result > 0

        except Exception as e:
            raise e

    async def close(self) -> None:
        """Close the Redis connection."""
        if self._redis:
            await self._redis.aclose()

            if hasattr(self._redis, "connection_pool"):
                await self._redis.connection_pool.disconnect()

            self._redis = None

    def _serialize_value(self, value: Any) -> bytes:
        """Serialize a Python object into bytes for storage in Redis.

        Attempts to use `msgpack` first, then falls back to `pickle` for complex types.

        Parameters
        ----------
        value: Any
            Python object to serialize.

        Returns
        -------
        bytes
            Serialized object as bytes.
        """
        try:
            return msgpack.packb(value, use_bin_type=True)

        except (ValueError, TypeError):
            return pickle.dumps(value)

    def _deserialize_data(self, data: bytes) -> Any:
        """Deserialize bytes retrieved from Redis back into a Python object.

        Attempts to use `msgpack` first, then falls back to `pickle`.

        Parameters
        ----------
        data: bytes
            Bytes retrieved from Redis.

        Returns
        -------
        Any
            Deserialized Python object.
        """
        try:
            return msgpack.unpackb(data, raw=False)

        except (msgpack.exceptions.ExtraData, ValueError, TypeError):
            return pickle.loads(data)
