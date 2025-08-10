import hashlib
import pickle
from typing import Any

import msgpack

from core.infrastructure.services import RedisService

from ..application.ports import CacheServiceInterface


class RedisCacheService(CacheServiceInterface):
    """Concrete implementation of `CacheServiceInterface` using Redis as the caching backend.

    Provides methods for storing, retrieving, and deleting data from Redis,
    handling serialization and deserialization of Python objects.
    """

    def __init__(self, redis_service: RedisService):
        """Initializes the CacheService.

        Establishes connection parameters for CacheService.

        Args:
            redis_service: Instance of RedisService.
        """
        self.redis_service = redis_service

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
            redis_client = await self.redis_service._get_redis()
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
            redis_client = await self.redis_service._get_redis()
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
            redis_client = await self.redis_service._get_redis()
            result = await redis_client.delete(key)
            return result > 0

        except Exception as e:
            raise e

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
