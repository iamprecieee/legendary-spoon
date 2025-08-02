from config.base import get_settings

from .services import DataSanitizer, RedisCacheService


async def get_data_sanitizer() -> DataSanitizer:
    """Provides a `DataSanitizer` instance.

    Returns:
        An instance of `DataSanitizer`.
    """
    return DataSanitizer()


async def get_redis_cache_service() -> RedisCacheService:
    """Provides a `RedisCacheService` instance.

    The service is initialized with Redis connection settings from the application settings.

    Returns:
        An instance of `RedisCacheService`.
    """
    settings = get_settings()

    return RedisCacheService(settings)
