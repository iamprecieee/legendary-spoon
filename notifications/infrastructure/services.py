import json
from datetime import UTC, datetime
from typing import Any, AsyncGenerator, Dict, List

from loguru import logger

from core.infrastructure.services import RedisService

from ..application.ports import NotificationChannelManager, NotificationPublisher
from ..domain.entities import NotificationChannel


class RedisNotificationChannelManager(NotificationChannelManager):
    """Redis-based implementation of notification channel management."""

    def __init__(self, redis_service: RedisService):
        """Initialize the Redis channel manager.

        Establishes connection parameters for CacheService.

        Args:
            redis_service: Instance of RedisService.
        """
        self.redis_service = redis_service
        self._channel_prefix = "notification_channels"

    async def register_channel(
        self, user_id: int, channel_id: str
    ) -> NotificationChannel:
        """Register a new notification channel in Redis.

        Stores channel data in Redis with expiration and adds to user's channel set.

        Parameters
        ----------
        user_id : int
            User ID
        channel_id : str
            Unique channel identifier

        Returns
        -------
        NotificationChannel
            Registered channel
        """
        redis_client = await self.redis_service._get_redis()

        channel = NotificationChannel(
            user_id=user_id,
            channel_id=channel_id,
            active=True,
            created_at=datetime.now(tz=UTC),
        )

        channel_key = f"{self._channel_prefix}:{channel_id}"
        channel_data = {
            "user_id": user_id,
            "channel_id": channel_id,
            "active": "true",
            "created_at": channel.created_at.isoformat(),
            "last_ping": datetime.now(tz=UTC).isoformat(),
        }

        await redis_client.hset(channel_key, mapping=channel_data)
        await redis_client.expire(channel_key, 3600)

        user_channels_key = f"{self._channel_prefix}:user:{user_id}"
        await redis_client.sadd(user_channels_key, channel_id)

        logger.info(f"Registered channel {channel_id} for user {user_id}")

        return channel

    async def unregister_channel(self, channel_id: str) -> bool:
        """Unregister a notification channel from Redis.

        Gets channel data before deletion, removes it from user's channel set,
        and delete channel data.

        Parameters
        ----------
        channel_id : str
            Channel identifier to unregister

        Returns
        -------
        bool
            True if successfully unregistered
        """
        redis_client = await self.redis_service._get_redis()

        channel_key = f"{self._channel_prefix}:{channel_id}"
        channel_data = await redis_client.hgetall(channel_key)

        if channel_data:
            user_id = channel_data.get("user_id")

            if user_id:
                user_channels_key = f"{self._channel_prefix}:user:{user_id}"
                await redis_client.srem(user_channels_key, channel_id)

            await redis_client.delete(channel_key)

            logger.info(f"Unregistered channel {channel_id}")
            return True

        return False

    async def get_user_channels(self, user_id: int) -> List[NotificationChannel]:
        """Get all active channels for a user from Redis.

        Parameters
        ----------
        user_id : int
            User ID

        Returns
        -------
        List[NotificationChannel]
            List of active channels
        """
        redis_client = await self.redis_service._get_redis()

        user_channels_key = f"{self._channel_prefix}:user:{user_id}"
        channel_ids = await redis_client.smembers(user_channels_key)

        channels = []
        for channel_id in channel_ids:
            channel_key = f"{self._channel_prefix}:{channel_id}"
            channel_data = await redis_client.hgetall(channel_key)

            if channel_data:
                channels.append(
                    NotificationChannel(
                        user_id=int(channel_data["user_id"]),
                        channel_id=channel_data["channel_id"],
                        is_active=channel_data.get("is_active", "true") == "true",
                        created_at=datetime.fromisoformat(channel_data["created_at"]),
                    )
                )

        return channels

    async def update_channel_heartbeat(self, channel_id: str) -> bool:
        """Update the last ping time for a channel to keep it alive.

        Parameters
        ----------
        channel_id : str
            Channel identifier

        Returns
        -------
        bool
            True if successfully updated
        """
        redis_client = await self.redis_service._get_redis()

        channel_key = f"{self._channel_prefix}:{channel_id}"
        exists = await redis_client.exists(channel_key)

        if exists:
            await redis_client.hset(
                channel_key, "last_ping", datetime.now().isoformat()
            )
            await redis_client.expire(channel_key, 3600)
            logger.info(f"Updated heartbeat for channel {channel_id}")
            return True

        return False


class RedisNotificationPublisher(NotificationPublisher):
    """Redis-based implementation of notification publishing using pub/sub."""

    def __init__(self, redis_service: RedisService):
        """Initialize the Redis notification publisher.

        Establishes connection parameters for CacheService.

        Args:
            redis_service: Instance of RedisService.
        """
        self.redis_service = redis_service

    async def publish(self, channel: str, notification: Dict[str, Any]) -> None:
        """Publish a notification to a Redis channel.

        Parameters
        ----------
        channel : str
            Channel name (e.g., "user:123" or "broadcast")
        notification : Dict[str, Any]
            Notification data to publish
        """
        redis_client = await self.redis_service._get_redis()

        if "timestamp" not in notification:
            notification["timestamp"] = str(datetime.now(tz=UTC).isoformat())

        message = json.dumps(notification)
        await redis_client.publish(f"notifications:{channel}", message)

    async def subscribe(self, channels: List[str]) -> AsyncGenerator[str, None]:
        """Subscribe to multiple notification channels.

        Parameters
        ----------
        channels : List[str]
            List of channel names to subscribe to

        Yields
        ------
        str
            JSON-encoded notification messages
        """
        redis_client = await self.redis_service._get_redis()
        pubsub = redis_client.pubsub()

        prefixed_channels = [f"notifications:{ch}" for ch in channels]

        await pubsub.subscribe(*prefixed_channels)

        try:
            async for message in pubsub.listen():
                if message["type"] == "message":
                    yield message["data"]
        finally:
            await pubsub.unsubscribe(*prefixed_channels)
            await pubsub.close()
