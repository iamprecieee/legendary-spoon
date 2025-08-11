from datetime import datetime
from typing import List

from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import and_, desc, or_, select

from cache.infrastructure.decorators import cache

from ..application.ports import NotificationRepository as DomainNotificationRepository
from ..domain.entities import Notification as DomainNotification
from ..domain.entities import NotificationPriority, NotificationType
from .models import Notification


class NotificationRepository(DomainNotificationRepository):
    """Concrete implementation of NotificationRepository for database-based notification management."""

    def __init__(self, session: AsyncSession) -> None:
        """Initialize the repository with a database session.

        Parameters
        ----------
        session : AsyncSession
            Asynchronous SQLAlchemy database session
        """
        self._session = session

    async def create(self, notification: DomainNotification) -> DomainNotification:
        """Create a new notification record in the database.

        Parameters
        ----------
        notification : DomainNotification
            Domain notification entity to be created

        Returns
        -------
        DomainNotification
            Created notification entity with database-assigned values

        Raises
        ------
        IntegrityError
            If there is a database integrity violation during creation
        Exception
            For other unexpected database errors
        """
        pydantic_notification = self._to_pydantic_model(notification)
        self._session.add(pydantic_notification)

        try:
            await self._session.commit()
            await self._session.refresh(pydantic_notification)
        except IntegrityError as e:
            await self._session.rollback()
            raise e
        except Exception as e:
            await self._session.rollback()
            raise e

        return self._to_domain_model(pydantic_notification)

    @cache(timeout_seconds=30, key_prefix="notifications:user")
    async def get_user_notifications(
        self,
        user_id: int,
        limit: int = 20,
        offset: int = 0,
        unread_only: bool = False,
        notification_type: NotificationType | None = None,
    ) -> List[DomainNotification]:
        """Retrieve notifications for a specific user with filtering options.

        Parameters
        ----------
        user_id : int
            ID of the user
        limit : int
            Maximum number of notifications to return
        offset : int
            Number of notifications to skip for pagination
        unread_only : bool
            If True, return only unread notifications
        notification_type : NotificationType | None, default=None
            Filter by specific notification type

        Returns
        -------
        List[DomainNotification]
            List of notifications matching the criteria
        """
        query = select(Notification).where(
            or_(
                Notification.recipient_id == user_id,
                Notification.recipient_id.is_(None),
            )
        )

        if unread_only:
            query = query.where(Notification.is_read == False)

        if notification_type:
            query = query.where(Notification.purpose == notification_type.value)

        query = query.order_by(desc(Notification.created_at))
        query = query.limit(limit).offset(offset)

        pydantic_notifications = await self._session.execute(query)
        pydantic_notifications = pydantic_notifications.scalars().all()

        return [
            self._to_domain_model(notification)
            for notification in pydantic_notifications
        ]

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
        result = await self._session.execute(
            select(Notification).where(
                and_(
                    Notification.id == notification_id,
                    or_(
                        Notification.recipient_id == user_id,
                        Notification.recipient_id == None,
                    ),
                )
            )
        )
        pydantic_notification = result.scalars().first()

        if pydantic_notification:
            pydantic_notification = pydantic_notification
            pydantic_notification.is_read = True
            self._session.add(pydantic_notification)

            try:
                await self._session.commit()
                return True
            except Exception as e:
                await self._session.rollback()
                raise e

        return False

    async def get_missed_notifications(
        self, user_id: int, last_timestamp: datetime, limit: int = 50
    ) -> List[DomainNotification]:
        """Get notifications for user created after specified timestamp.

        Parameters
        ----------
        user_id : int
            ID of the user
        last_timestamp : datetime
            Timestamp to filter notifications created after
        limit : int
            Maximum number of notifications to return

        Returns
        -------
        List[DomainNotification]
            List of notifications created after the specified timestamp"""
        query = (
            select(Notification)
            .where(
                and_(
                    or_(
                        Notification.recipient_id == user_id,
                        Notification.recipient_id.is_(None),
                    ),
                    Notification.created_at > last_timestamp,
                    Notification.is_read == False,
                )
            )
            .order_by(Notification.created_at.asc())
            .limit(limit)
        )

        pydantic_notifications = await self._session.execute(query)
        pydantic_notifications = pydantic_notifications.scalars().all()

        return [
            self._to_domain_model(notification)
            for notification in pydantic_notifications
        ]

    def _to_pydantic_model(
        self, domain_notification: DomainNotification
    ) -> Notification:
        """Convert a domain notification entity to a pydantic model.

        Parameters
        ----------
        domain_notification : DomainNotification
            Domain entity to convert

        Returns
        -------
        Notification
            Pydantic model instance
        """
        return Notification(
            title=domain_notification.title,
            message=domain_notification.message,
            purpose=domain_notification.purpose,
            priority=domain_notification.priority,
            recipient_id=domain_notification.recipient_id,
            sender_id=domain_notification.sender_id,
            notification_metadata=domain_notification.notification_metadata,
            is_read=domain_notification.is_read,
        )

    def _to_domain_model(
        self, pydantic_notification: Notification
    ) -> DomainNotification:
        """Convert a pydantic notification model to a domain entity.

        Parameters
        ----------
        pydantic_notification : Notification
            Pydantic model to convert

        Returns
        -------
        DomainNotification
            Domain notification entity instance
        """
        return DomainNotification(
            id=pydantic_notification.id,
            title=pydantic_notification.title,
            message=pydantic_notification.message,
            purpose=NotificationType(pydantic_notification.purpose),
            priority=NotificationPriority(pydantic_notification.priority),
            recipient_id=pydantic_notification.recipient_id,
            sender_id=pydantic_notification.sender_id,
            notification_metadata=pydantic_notification.notification_metadata,
            is_read=pydantic_notification.is_read,
            created_at=pydantic_notification.created_at,
        )
