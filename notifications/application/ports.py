from abc import ABC, abstractmethod
from typing import AsyncGenerator, List

from ..domain.entities import Notification as DomainNotification
from ..domain.entities import NotificationChannel as DomainNotificationChannel
from ..domain.entities import NotificationType


class NotificationRepository(ABC):
    """Abstract base class for notification data management.

    Defines the interface for interacting with notifications, including creation,
    retrieval by various identifiers, and performing state-altering actions.
    """

    @abstractmethod
    async def create(self, notification: DomainNotification) -> DomainNotification:
        """Store a new notification.

        Parameters
        ----------
        notification : DomainNotification
            Notification entity to create.

        Returns
        -------
        DomainNotification
            Created notification with ID assigned.
        """
        pass

    @abstractmethod
    async def get_user_notifications(
        self,
        user_id: int,
        limit: int = 20,
        offset: int = 0,
        unread_only: bool = False,
        notification_type: NotificationType | None = None,
    ) -> List[DomainNotification]:
        """Retrieve notifications for a specific user.

        Parameters
        ----------
        user_id : int
            ID of the user
        limit : int
            Maximum number of notifications to return
        offset : int
            Number of notifications to skip
        unread_only : bool
            If True, return only unread notifications
        notification_type : Optional[NotificationType]
            Filter by notification type

        Returns
        -------
        List[DomainNotification]
            List of notifications matching the criteria
        """
        pass

    @abstractmethod
    async def mark_as_read(self, notification_id: int, user_id: int) -> bool:
        """Mark a notification as read.

        Parameters
        ----------
        notification_id : int
            ID of the notification
        user_id : int
            ID of the user (for ownership verification)

        Returns
        -------
        bool
            True if successfully marked as read
        """
        pass


class NotificationChannelManager(ABC):
    """Abstract base class for managing SSE notification channels."""

    @abstractmethod
    async def register_channel(
        self, user_id: int, channel_id: str
    ) -> DomainNotificationChannel:
        """Register a new notification channel for a user.

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
        pass

    @abstractmethod
    async def unregister_channel(self, channel_id: str) -> bool:
        """Unregister a notification channel.

        Parameters
        ----------
        channel_id : str
            Channel identifier to unregister

        Returns
        -------
        bool
            True if successfully unregistered
        """
        pass

    @abstractmethod
    async def get_user_channels(self, user_id: int) -> List[DomainNotificationChannel]:
        """Get all active channels for a user.

        Parameters
        ----------
        user_id : int
            User ID

        Returns
        -------
        List[DomainNotificationChannel]
            List of active channels
        """
        pass


class NotificationPublisher(ABC):
    """Abstract base class for publishing notifications to subscribers."""

    @abstractmethod
    async def publish(self, channel: str, notification: DomainNotification) -> None:
        """Publish a notification to a specific channel.

        Parameters
        ----------
        channel : str
            Channel identifier (user-specific or broadcast)
        notification : DomainNotification
            Notification to publish
        """
        pass

    async def subscribe(self, channels: List[str]) -> AsyncGenerator[str, None]:
        """Subscribe to notifications on a specific channel.

        Parameters
        ----------
        channel : List[str]
            Channel identifier to subscribe to

        Yields
        ------
        str
            Serialized notification data
        """
        pass
