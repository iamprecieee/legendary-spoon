from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from config.database import get_database_session

from .repositories import UserRepository


async def get_user_repository(
    session: AsyncSession = Depends(get_database_session),
) -> UserRepository:
    """Provide a `UserRepository` instance.

    Parameters
    ----------
    session: AsyncSession
        Asynchronous SQLAlchemy database session, injected as a dependency.

    Returns
    -------
    UserRepository
        Instance of `UserRepository`.
    """
    return UserRepository(session)
