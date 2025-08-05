from abc import ABC, abstractmethod
from typing import Any


class CacheServiceInterface(ABC):
    """Abstract base class for cache-related services.

    Defines the interface for common cache operations like getting, setting,
    and deleting key-value pairs.
    """

    def get_cache_key(*args, **kwargs) -> str:
        """Generate a unique cache key based on function arguments.

        Returns
        -------
        str
            Cache key.
        """
        pass

    @abstractmethod
    async def get(self, key: str) -> Any:
        """Retrieve a value from the cache by its key.

        Parameters
        ----------
        key: str
            Unique key of the item to retrieve.

        Returns
        -------
        Any
            Cached value.
        """
        pass

    @abstractmethod
    async def set(self, key: str, value: Any, timeout: int | None = None) -> bool:
        """Set a key-value pair in the cache.

        Parameters
        ----------
        key: str
            Unique key for the item.
        value: Any
            Value to be cached.
        timeout: int | None, optional
            Expiration time in seconds.

        Returns
        -------
        bool

        """
        pass

    @abstractmethod
    async def delete(self, key: str) -> bool:
        """Delete a key-value pair from the cache.

        Parameters
        ----------
        key: str
            Key of the item to delete.

        Returns
        -------
        bool

        """
        pass
