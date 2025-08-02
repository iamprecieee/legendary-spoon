import hashlib
from functools import wraps
from typing import Callable

from loguru import logger

from ..factory import get_data_sanitizer, get_redis_cache_service


def cache_key(*args, **kwargs) -> str:
    """Generates a unique cache key based on function arguments.

    This function creates a consistent and unique string representation
    of the arguments passed to a cached function, which is then hashed.

    Args:
        *args: Positional arguments passed to the function.
        **kwargs: Keyword arguments passed to the function.

    Returns:
        A hexadecimal MD5 hash string representing the unique cache key.
    """
    key_parts = []

    for i, arg in enumerate(args):
        if i == 0 and hasattr(arg, "__dict__") and hasattr(arg, "__class__"):
            continue

        key_parts.append(f"arg{i}:{str(arg)}")

    for key, value in sorted(kwargs.items()):
        key_parts.append(f"{key}:{str(value)}")

    key_string = "|".join(key_parts)
    return hashlib.md5(key_string.encode()).hexdigest()


def cache(
    timeout_seconds: int | None, key_prefix: str = "", *args, **kwargs
) -> Callable[[Callable], Callable]:
    """A decorator for caching the results of asynchronous functions.

    The cache key is generated based on the function's arguments.
    If a result is found in the cache, it's returned immediately.
    Otherwise, the function is executed, its result is cached, and then returned.

    Args:
        timeout_seconds: The time in seconds before the cached item expires.
                         If None, the item does not expire (or uses a default cache setting).
        key_prefix: An optional prefix to add to the generated cache key for categorization.
        *args: Positional arguments passed to the decorator (not directly used for cache key).
        **kwargs: Keyword arguments passed to the decorator (not directly used for cache key).

    Returns:
        A decorator that can be applied to an asynchronous function.
    """

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            func_name = f"{func.__module__}.{func.__qualname__}"
            key_suffix = cache_key(*args, **kwargs)
            cache_key_full = (
                f"{key_prefix}:{func_name}:{key_suffix}"
                if key_prefix
                else f"{func_name}:{key_suffix}"
            )

            cache_service = await get_redis_cache_service()

            sanitizer = await get_data_sanitizer()
            sanitized_key = sanitizer.sanitize_for_logging(cache_key_full)

            try:
                cached_result = await cache_service.get(cache_key_full)
                if cached_result is not None:
                    logger.debug(f"🎯 Cache HIT for key: {sanitized_key}")
                    return cached_result

                logger.debug(f"🔍 Cache MISS for key: {sanitized_key}")
                result = await func(*args, **kwargs)

                await cache_service.set(cache_key_full, result, timeout_seconds)

                return result

            except Exception as e:
                exc_msg = sanitizer.sanitize_exception_for_logging(e)
                logger.error(f"🔴 Cache ERROR: {exc_msg}")
                return await func(*args, **kwargs)

        return async_wrapper

    return decorator
