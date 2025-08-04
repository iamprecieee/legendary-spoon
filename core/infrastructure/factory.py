from config.base import get_settings

from .services import DataSanitizer, RedisCacheService

_data_sanitizer = None
_redis_cache_service = None


async def get_data_sanitizer() -> DataSanitizer:
    """Provides a singleton `DataSanitizer` instance.

    Returns:
        An instance of `DataSanitizer`.
    """
    global _data_sanitizer

    if _data_sanitizer is None:
        _data_sanitizer = DataSanitizer()

    return _data_sanitizer


async def get_redis_cache_service() -> RedisCacheService:
    """Provides a singleton `RedisCacheService` instance.

    The service is initialized with Redis connection settings from the application settings.

    Returns:
        An instance of `RedisCacheService`.
    """
    global _redis_cache_service

    if _redis_cache_service is None:
        settings = get_settings()
        _redis_cache_service = RedisCacheService(settings)

    return _redis_cache_service


async def close_redis_cache_service():
    """Properly close the singleton Redis cache service."""
    global _redis_cache_service

    if _redis_cache_service:
        await _redis_cache_service.close()

        _redis_cache_service = None
