import json
import uuid
from datetime import datetime, timedelta, timezone
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
    """Business logic for establishing SSE connection for a user.

    Enhaced to handle missed notifications and real-time updates."""

    def __init__(
        self,
        user_id: int,
        publisher: NotificationPublisher,
        channel_manager: NotificationChannelManager,
        notification_repository: NotificationRepository,
    ) -> None:
        self.user_id = user_id
        self.publisher = publisher
        self.channel_manager = channel_manager
        self.notification_repository = notification_repository
        self.channel_id = str(uuid.uuid4())

    async def execute(self) -> AsyncGenerator[str, None]:
        """Execute the SSE connection establishment.

        Registers a channel and subscribes to notifications.
        If a last seen timestamp is provided, it fetches missed notifications
        and sends them before starting the real-time subscription.

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
            yield f"data: {
                json.dumps(
                    {
                        'type': 'connection',
                        'status': 'connected',
                        'channel_id': self.channel_id,
                    }
                )
            }\n\n"

            async for notification in self._send_missed_notifications():
                logger.opt(raw=True, colors=True).info(
                    sanitizer.sanitize_for_logging(notification)
                )
                yield notification

            user_channel = f"user:{self.user_id}"
            async for message in self.publisher.subscribe([user_channel, "broadcast"]):
                logger.opt(raw=True, colors=True).info(
                    sanitizer.sanitize_for_logging(message.decode("utf-8"))
                )
                await self.channel_manager.update_channel_heartbeat(self.channel_id)
                yield f"data: {message}\n\n"

        except Exception as e:
            raise Exception(f"SSE connection error for user {self.user_id}: {e}") from e

        finally:
            await self.channel_manager.unregister_channel(self.channel_id)
            logger.info(f"Closed SSE connection for user {self.user_id}")

    async def _send_missed_notifications(self) -> AsyncGenerator[str, None]:
        """Send notifications that were missed while user was offline.

        Gets the last connection timestamp or default to last 24 hours.

        Returns
        -------
        AsyncGenerator[str, None]
            SSE-formatted missed notifications
        """
        try:
            last_seen = await self.channel_manager.get_user_last_seen(self.user_id)

            if last_seen is None:
                last_seen = datetime.now(timezone.utc) - timedelta(hours=24)
                logger.info(
                    f"No last seen timestamp for user {self.user_id}, defaulting to last 24 hours"
                )
            else:
                logger.info(f"Last seen timestamp for user {self.user_id}: {last_seen}")

            missed_notifications = (
                await self.notification_repository.get_missed_notifications(
                    user_id=self.user_id, last_timestamp=last_seen
                )
            )

            for notification in missed_notifications:
                notification_data = {
                    **notification.__dict__,
                    "created_at": str(notification.created_at),
                    "type": "missed_notification",
                    "is_historical": True,
                }

                yield f"data: {json.dumps(notification_data)}\n\n"

        except Exception as e:
            logger.error(
                f"Error sending missed notifications to user {self.user_id}: {e}"
            )

    async def _get_missed_notifications(
        self, last_timestamp: datetime
    ) -> List[DomainNotification]:
        """Get notifications created after the given timestamp."""
        return await self.notification_repository.get_missed_notifications(
            user_id=self.user_id, last_timestamp=last_timestamp
        )


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


# # notifications/application/rules.py - Enhanced SSE Rule
# import json
# import uuid
# from datetime import datetime, timezone
# from typing import AsyncGenerator, List

# class EnhancedEstablishSSEConnectionRule:
#     """Enhanced SSE connection with missed notification delivery."""

#     def __init__(
#         self,
#         user_id: int,
#         publisher: NotificationPublisher,
#         channel_manager: NotificationChannelManager,
#         notification_repository: NotificationRepository,
#         last_seen_timestamp: datetime | None = None,  # New parameter
#     ) -> None:
#         self.user_id = user_id
#         self.publisher = publisher
#         self.channel_manager = channel_manager
#         self.notification_repository = notification_repository
#         self.last_seen_timestamp = last_seen_timestamp
#         self.channel_id = str(uuid.uuid4())

#     async def execute(self) -> AsyncGenerator[str, None]:
#         """Execute enhanced SSE connection with missed notifications."""
#         sanitizer = await get_data_sanitizer()

#         # 1. Register channel
#         await self.channel_manager.register_channel(
#             user_id=self.user_id,
#             channel_id=self.channel_id,
#         )

#         logger.info(f"Established SSE connection for user {self.user_id}")

#         try:
#             # 2. Send connection confirmation
#             yield f"data: {json.dumps({
#                 'type': 'connection',
#                 'status': 'connected',
#                 'channel_id': self.channel_id
#             })}\n\n"

#             # 3. ENHANCEMENT: Send missed notifications on connection
#             await self._send_missed_notifications()

#             # 4. Start listening for new real-time notifications
#             user_channel = f"user:{self.user_id}"
#             async for message in self.publisher.subscribe([user_channel, "broadcast"]):
#                 await self.channel_manager.update_channel_heartbeat(self.channel_id)
#                 yield f"data: {message}\n\n"

#         except Exception as e:
#             raise Exception(f"SSE connection error for user {self.user_id}: {e}") from e
#         finally:
#             await self.channel_manager.unregister_channel(self.channel_id)
#             logger.info(f"Closed SSE connection for user {self.user_id}")


# # Enhanced notification repository method
# class NotificationRepository(DomainNotificationRepository):


# # Enhanced SSE endpoint with last_seen tracking
# @router.get("/stream", response_class=StreamingResponse)
# async def enhanced_stream_notifications(
#     last_seen: datetime | None = None,  # Query parameter for last seen timestamp
#     publisher=Depends(get_notification_publisher),
#     channel_manager=Depends(get_notification_channel_manager),
#     notification_repository=Depends(get_notification_repository),
#     current_user: DomainUser = Depends(get_current_user),
# ):
#     """Enhanced SSE endpoint with missed notification delivery."""
#     logger.info(f"Establishing enhanced SSE connection for user {current_user.id}")

#     sse_rule = EnhancedEstablishSSEConnectionRule(
#         user_id=current_user.id,
#         publisher=publisher,
#         channel_manager=channel_manager,
#         notification_repository=notification_repository,
#         last_seen_timestamp=last_seen
#     )

#     async def event_generator():
#         """Generate SSE events with missed notifications."""
#         try:
#             async for event in sse_rule.execute():
#                 yield event
#                 await asyncio.sleep(0.1)

#         except asyncio.CancelledError:
#             logger.info(f"SSE connection cancelled for user {current_user.id}")
#             raise
#         except Exception as e:
#             logger.error(f"SSE error for user {current_user.id}: {e}")
#             yield "data: {'type': 'error', 'message': 'Connection error'}\n\n"

#     return StreamingResponse(
#         event_generator(),
#         media_type="text/event-stream",
#         headers={
#             "Cache-Control": "no-cache",
#             "Connection": "keep-alive",
#             "X-Accel-Buffering": "no",
#         },
#     )
