from typing import Any, Dict

from pydantic import BaseModel, Field

from ..domain.entities import NotificationPriority, NotificationType


class CreateNotificationRequest(BaseModel):
    """Request model for creating a new notification.

    Attributes
    ----------
    title : str
        Brief title of the notification
    message : str
        Detailed notification message
    type : NotificationType
        Category of the notification
    priority : NotificationPriority
        Urgency level of the notification
    recipient_id : int | None
        User ID of the recipient, None for broadcast
    notification_metadata : Dict[str, Any]
        Additional data associated with the notification
    """

    title: str
    message: str
    purpose: NotificationType
    priority: NotificationPriority = NotificationPriority.MEDIUM
    recipient_id: int | None = None
    notification_metadata: Dict[str, Any] = Field(default_factory=dict)
