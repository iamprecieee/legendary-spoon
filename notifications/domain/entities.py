from datetime import datetime
from enum import StrEnum
from typing import Any, Dict

from pydantic import Field, dataclasses


class NotificationType(StrEnum):
    """Notification types for categorization and filtering."""

    SYSTEM = "system"
    USER = "user"
    UPDATE = "update"


class NotificationPriority(StrEnum):
    """Priority levels for notifications categorization and filtering."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclasses.dataclass
class Notification:
    """Core domain entity representing a notification.

    Attributes
    ----------
    title : str
        Brief title of the notification.
    message : str
        Detailed notification message.
    purpose : NotificationType
        Category of the notification.
    priority : NotificationPriority
        Urgency level of the notification.
    recipient_id : int | None, optional
        User ID of the recipient.
    sender_id : int | None, optional
        User ID of the sender, None for system notifications.
    notification_metadata : Dict[str, Any]
        Additional data associated with the notification.
    is_read: bool, default=False
        Boolean indicating if the notification has been read.
    created_at: datetime | None, optional
        Datetime when notification was created.
    id: int | None, optional
        Unique identifier for user.
    """

    title: str
    message: str
    purpose: str = NotificationType.SYSTEM
    priority: str = NotificationPriority.MEDIUM
    sender_id: int | None = None
    recipient_id: int | None = None
    notification_metadata: Dict[str, Any] = Field(default_factory={})
    is_read: bool = False
    created_at: datetime | None = None
    id: int | None = None


@dataclasses.dataclass
class NotificationChannel:
    """Core domain entity representing a notification delivery channel.

    Attributes
    ----------
    user_id : int
        User ID associated with this channel.
    channel_id : str
        Unique identifier for the server-side event connection.
    active : bool, default=True
        Boolean indicating if the channel is active.
    created_at : datetime | None, optional
        Datetime when notification was created.
    """

    user_id: int
    channel_id: str
    is_active: bool = True
    created_at: datetime | None = None
