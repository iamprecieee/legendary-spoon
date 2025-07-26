from datetime import datetime

from pydantic import BaseModel


class UserResponse(BaseModel):
    id: int
    email: str
    is_active: bool
    social_id: str | None = None
    created_at: datetime
