import asyncio

from fastapi import APIRouter, Depends, status
from fastapi.responses import StreamingResponse
from loguru import logger

from authentication.infrastructure.factory import get_current_user
from core.presentation.responses import SuccessResponse
from users.domain.entities import User as DomainUser

from ..application.rules import (
    CreateNotificationRule,
    EstablishSSEConnectionRule,
    GetUserNotificationsRule,
    MarkNotificationReadRule,
)
from ..domain.entities import NotificationType
from ..infrastructure.factory import (
    get_notification_channel_manager,
    get_notification_publisher,
    get_notification_repository,
)
from .requests import CreateNotificationRequest
from .responses import NotificationListResponse, NotificationResponse

router = APIRouter(prefix="/notifications")


@router.post("/", response_model=SuccessResponse, status_code=status.HTTP_201_CREATED)
async def create_notification(
    request: CreateNotificationRequest,
    notification_repository=Depends(get_notification_repository),
    publisher=Depends(get_notification_publisher),
    channel_manager=Depends(get_notification_channel_manager),
    current_user: DomainUser = Depends(get_current_user),
):
    """Create a new notification.

    Creates a notification and publishes it to the appropriate channels
    for real-time delivery via SSE.

    Parameters
    ----------
    request : CreateNotificationRequest
        Notification creation request data
    repository
        Dependency-injected notification repository
    publisher
        Dependency-injected notification publisher
    channel_manager
        Dependency-injected channel manager
    current_user : DomainUser
        Current authenticated user

    Returns
    -------
    SuccessResponse
        Response containing the created notification
    """
    create_notification_rule = CreateNotificationRule(
        title=request.title,
        message=request.message,
        purpose=request.purpose,
        priority=request.priority,
        recipient_id=request.recipient_id,
        sender_id=current_user.id,
        notification_metadata=request.notification_metadata,
        notification_repository=notification_repository,
        publisher=publisher,
        channel_manager=channel_manager,
    )

    created_notification = await create_notification_rule.execute()

    return SuccessResponse(
        data=NotificationResponse(
            id=created_notification.id,
            title=created_notification.title,
            message=created_notification.message,
            purpose=created_notification.purpose,
            priority=created_notification.priority,
            recipient_id=created_notification.recipient_id,
            sender_id=created_notification.sender_id,
            notification_metadata=created_notification.notification_metadata,
            is_read=created_notification.is_read,
            created_at=created_notification.created_at,
        ),
        message="Notification created successfully",
    )


@router.get("/", response_model=SuccessResponse, status_code=status.HTTP_200_OK)
async def get_notifications(
    limit: int,
    offset: int,
    unread_only: bool = False,
    notification_type: NotificationType | None = None,
    notification_repository=Depends(get_notification_repository),
    current_user: DomainUser = Depends(get_current_user),
):
    """Get notifications for the current user.

    Retrieves a paginated list of notifications with optional filtering
    by read status and notification type.

    Parameters
    ----------
    limit : int
        Maximum number of notifications to return (1-100)
    offset : int
        Number of notifications to skip for pagination
    unread_only : bool
        If True, return only unread notifications
    notification_type : Optional[NotificationType]
        Filter by specific notification type
    repository
        Dependency-injected notification repository
    current_user : DomainUser
        Current authenticated user

    Returns
    -------
    SuccessResponse
        Response containing the list of notifications
    """
    get_notifications_rule = GetUserNotificationsRule(
        user_id=current_user.id,
        notification_repository=notification_repository,
        limit=limit,
        offset=offset,
        unread_only=unread_only,
        notification_type=notification_type,
    )

    notifications, unread_count = await get_notifications_rule.execute()

    response_data = NotificationListResponse(
        notifications=[
            NotificationResponse(
                id=n.id,
                title=n.title,
                message=n.message,
                purpose=n.purpose,
                priority=n.priority,
                recipient_id=n.recipient_id,
                sender_id=n.sender_id,
                notification_metadata=n.notification_metadata,
                is_read=n.is_read,
                created_at=n.created_at,
            )
            for n in notifications
        ],
        total=len(notifications),
        unread_count=unread_count,
    )

    return SuccessResponse(
        data=response_data,
        message="Notifications retrieved successfully",
    )


@router.put(
    "/read/{notification_id}",
    response_model=SuccessResponse,
    status_code=status.HTTP_200_OK,
)
async def mark_notification_read(
    notification_id: int,
    notification_repository=Depends(get_notification_repository),
    current_user: DomainUser = Depends(get_current_user),
):
    """Mark a specific notification as read.

    Parameters
    ----------
    notification_id : int
        ID of the notification to mark as read
    repository
        Dependency-injected notification repository
    current_user : DomainUser
        Current authenticated user

    Returns
    -------
    SuccessResponse
        Response indicating success or failure
    """
    mark_notification_rule = MarkNotificationReadRule(
        notification_id=notification_id,
        user_id=current_user.id,
        notification_repository=notification_repository,
    )

    success = await mark_notification_rule.execute()

    return SuccessResponse(
        data={"marked_as_read": success},
        message=(
            "Notification marked as read"
            if success
            else "Failed to mark notification as read"
        ),
    )


@router.get("/stream", response_class=StreamingResponse)
async def stream_notifications(
    publisher=Depends(get_notification_publisher),
    channel_manager=Depends(get_notification_channel_manager),
    notification_repository=Depends(get_notification_repository),
    current_user: DomainUser = Depends(get_current_user),
):
    """Establish Server-Sent Events connection for real-time notifications.

    Opens a persistent connection for streaming notifications to the client
    using Server-Sent Events (SSE) protocol,
    and includes automatic missed notification delivery.

    Parameters
    ----------
    publisher
        Dependency-injected notification publisher
    channel_manager
        Dependency-injected channel manager
    notification_repository
        Dependency-injected notification repository
    current_user : DomainUser
        Current authenticated user

    Returns
    -------
    StreamingResponse
        SSE stream of notifications
    """
    logger.info(f"Establishing SSE connection for user {current_user.id}")

    sse_rule = EstablishSSEConnectionRule(
        user_id=current_user.id,
        publisher=publisher,
        notification_repository=notification_repository,
        channel_manager=channel_manager,
    )

    async def event_generator():
        """Generate SSE events with heartbeat to keep connection alive."""
        try:
            sse_task = sse_rule.execute()

            async for event in sse_task:
                yield event

                await asyncio.sleep(0.1)

        except asyncio.CancelledError:
            logger.info(f"SSE connection cancelled for user {current_user.id}")
            raise
        except Exception as e:
            logger.error(f"SSE error for user {current_user.id}: {e}")
            yield "data: {'type': 'error', 'message': 'Connection error'}\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
