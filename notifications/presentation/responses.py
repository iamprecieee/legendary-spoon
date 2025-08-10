from datetime import datetime
from typing import Any, Dict, List

from pydantic import BaseModel


class NotificationResponse(BaseModel):
    """Response model for a notification.

    Attributes
    ----------
    id : int
        Unique identifier of the notification
    title : str
        Brief title of the notification
    message : str
        Detailed notification message
    type : str
        Category of the notification
    priority : str
        Urgency level of the notification
    recipient_id : int | None
        User ID of the recipient
    sender_id : int | None
        User ID of the sender
    notification_metadata : Dict[str, Any]
        Additional data associated with the notification
    is_read : bool
        Whether the notification has been read
    created_at : datetime
        Timestamp of notification creation
    """

    id: int
    title: str
    message: str
    purpose: str
    priority: str
    recipient_id: int | None = None
    sender_id: int | None = None
    notification_metadata: Dict[str, Any]
    is_read: bool
    created_at: datetime


class NotificationListResponse(BaseModel):
    """Response model for a list of notifications.

    Attributes
    ----------
    notifications : List[NotificationResponse]
        List of notifications
    total : int
        Total number of notifications matching criteria
    unread_count : int
        Number of unread notifications
    """

    notifications: List[NotificationResponse]
    total: int
    unread_count: int
