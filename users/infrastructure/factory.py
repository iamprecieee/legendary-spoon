from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from config.database import get_database_session

from .repositories import UserRepository


async def get_user_repository(
    session: AsyncSession = Depends(get_database_session),
) -> UserRepository:
    """Provides a `UserRepository` instance.

    Args:
        session: An asynchronous SQLAlchemy database session, injected as a dependency.

    Returns:
        An instance of `UserRepository`.
    """
    return UserRepository(session)
