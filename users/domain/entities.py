import re
from datetime import datetime

from pydantic import dataclasses, field_validator


@dataclasses.dataclass
class User:
    """Represents a user in the domain layer.

    Attributes:
        email: The unique email address of the user.
        password: The hashed password of the user (optional, e.g., for OAuth users).
        is_active: A boolean indicating if the user account is active (default: True).
        created_at: The datetime when the user account was created (optional).
        social_id: The ID from a social login provider if linked (optional).
        id: The unique identifier for the user (optional).
    """

    email: str
    password: str
    is_active: bool = True
    created_at: datetime | None = None
    social_id: str | None = None
    id: int | None = None

    @field_validator("email")
    @classmethod
    def ensure_valid_email(cls, value):
        """Validates the format of the email address.

        Args:
            value: The email string to validate.

        Returns:
            The validated email string.

        Raises:
            ValueError: If the email address format is invalid.
        """
        if not re.fullmatch(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", value):
            raise ValueError("Email address is invalid.")

        return value
