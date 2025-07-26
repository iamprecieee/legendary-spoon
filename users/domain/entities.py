import re
from datetime import datetime

from pydantic import dataclasses, field_validator


@dataclasses.dataclass
class User:
    email: str
    password: str = ""  # Optional for OAuth users
    is_active: bool = True
    created_at: datetime | None = None
    social_id: str | None = None
    id: int | None = None

    @field_validator("email")
    @classmethod
    def ensure_valid_email(cls, value):
        if not re.fullmatch(r"^[a-zA-Z]+[\w\.-]+@[\w\.-]+\.[a-z\.]+", value):
            raise ValueError("Email is invalid.")
        return value
