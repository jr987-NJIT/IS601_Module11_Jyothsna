"""Pydantic schemas for calculation data validation and serialization."""
from datetime import datetime
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field, field_validator, ConfigDict


class CalculationType(str, Enum):
    """Enumeration for calculation operation types."""
    ADD = "Add"
    SUBTRACT = "Subtract"
    MULTIPLY = "Multiply"
    DIVIDE = "Divide"


class CalculationCreate(BaseModel):
    """
    Schema for creating a new calculation.
    Used when requesting a mathematical operation.
    """
    a: float = Field(..., description="First operand")
    b: float = Field(..., description="Second operand")
    type: CalculationType = Field(..., description="Type of operation (Add, Subtract, Multiply, Divide)")
    user_id: Optional[int] = Field(None, description="Optional user ID to associate with calculation")

    @field_validator('type')
    @classmethod
    def validate_division_by_zero(cls, v, info):
        """Validate that divisor is not zero for division operations."""
        # This runs after all fields are set, so we can check b
        if hasattr(info, 'data') and 'b' in info.data:
            if v == CalculationType.DIVIDE and info.data['b'] == 0:
                raise ValueError("Division by zero is not allowed")
        return v

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "a": 10.5,
                "b": 5.2,
                "type": "Add",
                "user_id": 1
            }
        }
    )


class CalculationRead(BaseModel):
    """
    Schema for reading calculation data.
    Returns calculation information including the computed result.
    """
    id: int
    a: float
    b: float
    type: str
    result: float
    user_id: Optional[int]
    created_at: datetime

    model_config = ConfigDict(
        from_attributes=True,
        json_schema_extra={
            "example": {
                "id": 1,
                "a": 10.5,
                "b": 5.2,
                "type": "Add",
                "result": 15.7,
                "user_id": 1,
                "created_at": "2024-01-01T12:00:00Z"
            }
        }
    )


class CalculationUpdate(BaseModel):
    """
    Schema for updating calculation information.
    All fields are optional.
    """
    a: Optional[float] = None
    b: Optional[float] = None
    type: Optional[CalculationType] = None
    user_id: Optional[int] = None

    @field_validator('type')
    @classmethod
    def validate_division_by_zero(cls, v, info):
        """Validate that divisor is not zero for division operations."""
        if hasattr(info, 'data') and 'b' in info.data:
            if v == CalculationType.DIVIDE and info.data['b'] is not None and info.data['b'] == 0:
                raise ValueError("Division by zero is not allowed")
        return v

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "a": 20.0,
                "b": 4.0
            }
        }
    )
