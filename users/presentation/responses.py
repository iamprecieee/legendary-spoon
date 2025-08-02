from datetime import datetime

from pydantic import BaseModel


class UserResponse(BaseModel):
    """Response model for user data.

    Represents the structure of user information returned by the API.

    Attributes:
        id: The unique identifier of the user.
        email: The email address of the user.
        is_active: A boolean indicating if the user account is active.
        social_id: The ID from a social login provider if linked (optional).
        created_at: The datetime when the user account was created.
    """

    id: int
    email: str
    is_active: bool
    social_id: str | None = None
    created_at: datetime
