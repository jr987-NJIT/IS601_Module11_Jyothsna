"""Pydantic schemas for user data validation and serialization."""
from datetime import datetime
from pydantic import BaseModel, EmailStr, Field, ConfigDict


class UserCreate(BaseModel):
    """
    Schema for creating a new user.
    Used when registering a new user account.
    """
    username: str = Field(..., min_length=3, max_length=50, description="Username for the account")
    email: EmailStr = Field(..., description="Valid email address")
    password: str = Field(..., min_length=8, max_length=100, description="Password (minimum 8 characters)")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "username": "johndoe",
                "email": "johndoe@example.com",
                "password": "securepassword123"
            }
        }
    )


class UserRead(BaseModel):
    """
    Schema for reading user data.
    Returns user information without exposing the password hash.
    """
    id: int
    username: str
    email: str
    created_at: datetime

    model_config = ConfigDict(
        from_attributes=True,
        json_schema_extra={
            "example": {
                "id": 1,
                "username": "johndoe",
                "email": "johndoe@example.com",
                "created_at": "2024-01-01T12:00:00Z"
            }
        }
    )


class UserUpdate(BaseModel):
    """
    Schema for updating user information.
    All fields are optional.
    """
    username: str | None = Field(None, min_length=3, max_length=50)
    email: EmailStr | None = None
    password: str | None = Field(None, min_length=8, max_length=100)

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "email": "newemail@example.com"
            }
        }
    )


# Import calculation schemas
from app.schemas.calculation import (  # noqa: E402
    CalculationCreate,
    CalculationRead,
    CalculationUpdate,
    CalculationType
)

__all__ = [
    "UserCreate",
    "UserRead",
    "UserUpdate",
    "CalculationCreate",
    "CalculationRead",
    "CalculationUpdate",
    "CalculationType"
]
