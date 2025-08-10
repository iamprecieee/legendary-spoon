from config.base import get_settings

from .services import DataSanitizer, RedisService

_data_sanitizer = None
_redis_service = None


async def get_data_sanitizer() -> DataSanitizer:
    """Provide a singleton `DataSanitizer` instance.

    Returns
    -------
    DataSanitizer
        Instance of `DataSanitizer`.
    """
    global _data_sanitizer

    if _data_sanitizer is None:
        _data_sanitizer = DataSanitizer()

    return _data_sanitizer


async def get_redis_service() -> RedisService:
    """Provide a singleton `RedisService` instance.

    Returns
    -------
    RedisService
        Instance of `RedisService`.
    """
    global _redis_service

    if _redis_service is None:
        settings = get_settings()
        _redis_service = RedisService(settings)

    return _redis_service


async def close_redis_service():
    """Close the singleton Redis service properly."""
    global _redis_service

    if _redis_service:
        await _redis_service.close()

        _redis_service = None
