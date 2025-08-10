from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from config.database import get_database_session
from core.infrastructure.factory import get_redis_service

from .repositories import NotificationRepository
from .services import RedisNotificationChannelManager, RedisNotificationPublisher


async def get_notification_channel_manager() -> RedisNotificationChannelManager:
    """Provide a RedisNotificationChannelManager instance.

    Returns
    -------
    RedisNotificationChannelManager
        Instance of RedisNotificationChannelManager
    """
    redis_service = await get_redis_service()
    return RedisNotificationChannelManager(redis_service)


async def get_notification_publisher() -> RedisNotificationPublisher:
    """Provide a RedisNotificationPublisher instance.

    Returns
    -------
    RedisNotificationPublisher
        Instance of RedisNotificationPublisher
    """
    redis_service = await get_redis_service()
    return RedisNotificationPublisher(redis_service)


async def get_notification_repository(
    session: AsyncSession = Depends(get_database_session),
) -> NotificationRepository:
    """Provide a NotificationRepository instance.

    Parameters
    ----------
    session : AsyncSession
        Asynchronous SQLAlchemy database session, injected as a dependency

    Returns
    -------
    NotificationRepository
        Instance of NotificationRepository
    """
    return NotificationRepository(session)
