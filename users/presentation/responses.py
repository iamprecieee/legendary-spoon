from datetime import datetime

from pydantic import BaseModel


class UserResponse(BaseModel):
    """Response model for user data.

    Represents the structure of user information returned by the API.

    Attributes
    ----------
    id: int
        User's ID.
    email: str
        User's email address.
    is_active: bool
        User's active status.
    social_id: str | None, optional
        User's social id.
    created_at: datetime
        User's creation timestamp.
    """

    id: int
    email: str
    is_active: bool
    social_id: str | None = None
    created_at: datetime
