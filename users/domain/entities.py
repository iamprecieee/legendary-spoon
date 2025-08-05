import re
from datetime import datetime

from pydantic import dataclasses, field_validator


@dataclasses.dataclass
class User:
    """Core domain entity representing a user account in the system.

    Attributes
    ----------
    email: str
        Unique email address of user.
    password: str
        Hashed password of user.
    is_active: bool, default=True
        Boolean indicating if user account is active.
    created_at: datetime | None, optional
        Datetime when user account was created.
    social_id: str | None, optional
        ID from a social login provider if linked.
    id: int | None, optional
        Unique identifier for user.

    Note
    ----
    Password field should always contain hashed values.
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
        """Perform email format validation using regex pattern matching.

        Parameters
        ----------
        value: str
            The email string to validate.

        Returns
        -------
        str
            The validated email string.

        Raises
        ------
        ValueError
            If the email address format is invalid.
        """
        if not re.fullmatch(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", value):
            raise ValueError("Email address is invalid.")

        return value
