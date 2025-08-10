from core.infrastructure.factory import get_redis_service

from .services import RedisCacheService


async def get_redis_cache_service() -> RedisCacheService:
    """Provide a `RedisCacheService` instance.

    Returns
    -------
    RedisCacheService
        Instance of `RedisCacheService`.
    """
    redis_service = await get_redis_service()

    return RedisCacheService(redis_service)
