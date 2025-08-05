from functools import wraps
from typing import Callable

from loguru import logger

from .factory import get_data_sanitizer, get_redis_cache_service


def cache(
    timeout_seconds: int | None, key_prefix: str = "", *args, **kwargs
) -> Callable[[Callable], Callable]:
    """Decorator for caching the results of asynchronous functions.

    Cache key is generated based on the function's arguments.
    If a result is found in the cache, return it immediately.
    Otherwise, execute the function, cache its result, and then return it.

    Parameters
    ----------
    timeout_seconds: int | None, optional
        Time in seconds before the cached item expires.
        If None, item does not expire (or uses a default cache setting).
    key_prefix: str, default=""
        Optional prefix to add to the generated cache key for categorization.
    *args
        Positional arguments passed to the decorator.
    **kwargs
        Keyword arguments passed to the decorator.

    Returns
    -------
    Callable[[Callable], Callable]
        Decorator that can be applied to an asynchronous function.
    """

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            func_name = f"{func.__module__}.{func.__qualname__}"

            cache_service = await get_redis_cache_service()
            cache_key = cache_service.get_cache_key(
                key_prefix, func_name, *args, **kwargs
            )

            sanitizer = await get_data_sanitizer()
            sanitized_key = sanitizer.sanitize_for_logging(cache_key)

            try:
                cached_result = await cache_service.get(cache_key)
                if cached_result is not None:
                    logger.debug(f"🎯 Cache HIT for key: {sanitized_key}")
                    return cached_result

                logger.debug(f"🔍 Cache MISS for key: {sanitized_key}")
                result = await func(*args, **kwargs)

                await cache_service.set(cache_key, result, timeout_seconds)
                return result

            except Exception as e:
                exc_msg = sanitizer.sanitize_exception_for_logging(e)
                logger.error(f"🔴 Cache ERROR: {exc_msg}")
                return await func(*args, **kwargs)

        return async_wrapper

    return decorator
