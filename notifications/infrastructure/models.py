from datetime import UTC, datetime
from typing import Any, Dict

from sqlmodel import JSON, Column, Field, SQLModel

from ..domain.entities import NotificationPriority, NotificationType


class Notification(SQLModel, table=True):
    """SQLModel table representation for the Notification entity.

    Attributes
    ----------
    id : int | None
        Primary key, auto-incrementing integer
    title : str
        Brief title of the notification
    message : str
        Detailed notification message
    purpose : str
        Category of the notification (stored as string)
    priority : str
        Urgency level of the notification (stored as string)
    recipient_id : int | None
        User ID of the recipient, nullable for broadcasts
    sender_id : int | None
        User ID of the sender, nullable for system notifications
    notification_metadata : Dict[str, Any]
        Additional JSON data associated with the notification
    is_read : bool
        Whether the notification has been read
    created_at : datetime
        Timestamp of notification creation
    """

    id: int | None = Field(default=None, primary_key=True)
    title: str = Field(nullable=False)
    message: str = Field(nullable=False)
    purpose: str = Field(default=NotificationType.SYSTEM.value, index=True)
    priority: str = Field(default=NotificationPriority.MEDIUM.value)
    sender_id: int | None = Field(default=None, foreign_key="user.id", nullable=True)
    recipient_id: int | None = Field(
        default=None, foreign_key="user.id", nullable=True, index=True
    )
    notification_metadata: Dict[str, Any] = Field(
        default_factory=dict, sa_column=Column(JSON)
    )
    is_read: bool = Field(default=False, index=True)
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(tz=UTC), index=True
    )
