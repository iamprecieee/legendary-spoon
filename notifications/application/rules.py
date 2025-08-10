import json
import uuid
from typing import Any, AsyncGenerator, Dict, List, Tuple

from loguru import logger
from pydantic import Field

from core.infrastructure.factory import get_data_sanitizer

from ..domain.entities import Notification as DomainNotification
from ..domain.entities import NotificationType
from .ports import (
    NotificationChannelManager,
    NotificationPublisher,
    NotificationRepository,
)


class EstablishSSEConnectionRule:
    """Business logic for establishing SSE connection for a user."""

    def __init__(
        self,
        user_id: int,
        publisher: NotificationPublisher,
        channel_manager: NotificationChannelManager,
    ) -> None:
        self.user_id = user_id
        self.publisher = publisher
        self.channel_manager = channel_manager
        self.channel_id = str(uuid.uuid4())

    async def execute(self) -> AsyncGenerator[str, None]:
        """Execute the SSE connection establishment.

        Registers a channel and subscribes to notifications.

        Yields
        ------
        str
            SSE-formatted notification data
        """
        sanitizer = await get_data_sanitizer()

        await self.channel_manager.register_channel(
            user_id=self.user_id,
            channel_id=self.channel_id,
        )
        logger.info(
            f"Established SSE connection for user {self.user_id} with channel {self.channel_id}"
        )

        try:
            user_channel = f"user:{self.user_id}"
            yield f"data: {json.dumps({'type': 'connection', 'status': 'connected', 'channel_id': self.channel_id})}\n\n"

            async for message in self.publisher.subscribe([user_channel, "broadcast"]):
                logger.opt(raw=True, colors=True).info(
                    sanitizer.sanitize_for_logging(message.decode("utf-8"))
                )
                print(sanitizer.sanitize_for_logging(message.decode("utf-8")))
                await self.channel_manager.update_channel_heartbeat(self.channel_id)
                yield f"data: {message}\n\n"

        except Exception as e:
            raise Exception(f"SSE connection error for user {self.user_id}: {e}") from e

        finally:
            await self.channel_manager.unregister_channel(self.channel_id)
            logger.info(f"Closed SSE connection for user {self.user_id}")


class CreateNotificationRule:
    """Business logic for creating and dispatching notifications."""

    def __init__(
        self,
        title: str,
        message: str,
        purpose: str,
        priority: str,
        notification_repository: NotificationRepository,
        publisher: NotificationPublisher,
        channel_manager: NotificationChannelManager,
        sender_id: int | None = None,
        recipient_id: int | None = None,
        notification_metadata: Dict[str, Any] = Field(default_factory={}),
    ) -> None:
        self.title = title
        self.message = message
        self.purpose = purpose
        self.priority = priority
        self.sender_id = sender_id
        self.recipient_id = recipient_id
        self.notification_metadata = notification_metadata
        self.notification_repository = notification_repository
        self.publisher = publisher
        self.channel_manager = channel_manager

    async def execute(self) -> DomainNotification:
        """Execute the notification creation process.

        Creates a notification in the database and publishes it to relevant channels.

        Returns
        -------
        DomainNotification
            Created notification entity
        """
        created_notification = await self.notification_repository.create(
            DomainNotification(
                title=self.title,
                message=self.message,
                purpose=self.purpose,
                priority=self.priority,
                sender_id=self.sender_id,
                recipient_id=self.recipient_id,
                notification_metadata=self.notification_metadata,
            )
        )
        notification_data = created_notification.__dict__.copy()
        notification_data["created_at"] = str(notification_data["created_at"])

        if created_notification.recipient_id is not None:
            channel = f"user:{created_notification.recipient_id}"
            await self.publisher.publish(channel, notification_data)
            logger.info(
                f"Published notification {created_notification.id} to {channel}"
            )
        else:
            await self.publisher.publish("broadcast", notification_data)
            logger.info(f"Published broadcast notification {created_notification.id}")

        return created_notification


class GetUserNotificationsRule:
    """Business logic for retrieving user notifications."""

    def __init__(
        self,
        user_id: int,
        notification_repository: NotificationRepository,
        limit: int = 20,
        offset: int = 0,
        unread_only: bool = False,
        notification_type: NotificationType | None = None,
    ) -> None:
        self.user_id = user_id
        self.notification_repository = notification_repository
        self.limit = limit
        self.offset = offset
        self.unread_only = unread_only
        self.notification_type = notification_type

    async def execute(self) -> Tuple[List[DomainNotification], int]:
        """Execute the notification retrieval process.

        Returns
        -------
        Tuple[List[DomainNotification], int]
            Tuple containing list of notifications and unread count
        """
        notifications_list = await self.notification_repository.get_user_notifications(
            user_id=self.user_id,
            limit=self.limit,
            offset=self.offset,
            unread_only=self.unread_only,
            notification_type=self.notification_type,
        )
        unread_count = len([n for n in notifications_list if not n.is_read])
        return notifications_list, unread_count


class MarkNotificationReadRule:
    """Business logic for marking notifications as read."""

    def __init__(
        self,
        notification_id: int,
        user_id: int,
        notification_repository: NotificationRepository,
    ) -> None:
        self.notification_id = notification_id
        self.user_id = user_id
        self.notification_repository = notification_repository

    async def execute(self) -> bool:
        """Execute the mark as read process.

        Returns
        -------
        bool
            True if successfully marked as read
        """
        return await self.notification_repository.mark_as_read(
            notification_id=self.notification_id,
            user_id=self.user_id,
        )
