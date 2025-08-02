from abc import ABC, abstractmethod
from typing import Any


class CacheServiceInterface(ABC):
    """Abstract base class for cache-related services.

    Defines the interface for common cache operations like getting, setting,
    and deleting key-value pairs.
    """

    @abstractmethod
    async def get(self, key: str) -> Any:
        """Retrieves a value from the cache by its key.

        Args:
            key: The unique key of the item to retrieve.

        Returns:
            The cached value, or None if the key does not exist.
        """
        pass

    @abstractmethod
    async def set(self, key: str, value: Any, timeout: int | None = None) -> bool:
        """Sets a key-value pair in the cache.

        Args:
            key: The unique key for the item.
            value: The value to be cached.
            timeout: The expiration time in seconds (optional). If None, uses default.

        Returns:
            True if the operation was successful, False otherwise.
        """
        pass

    @abstractmethod
    async def delete(self, key: str) -> bool:
        """Deletes a key-value pair from the cache.

        Args:
            key: The key of the item to delete.

        Returns:
            True if the item was successfully deleted, False otherwise.
        """
        pass
