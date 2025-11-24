"""Unit tests for calculation Pydantic schemas."""
import pytest
from pydantic import ValidationError
from app.schemas.calculation import (
    CalculationCreate,
    CalculationRead,
    CalculationUpdate,
    CalculationType
)


class TestCalculationType:
    """Test suite for CalculationType enum."""
    
    def test_calculation_type_values(self):
        """Test that CalculationType has correct values."""
        assert CalculationType.ADD.value == "Add"
        assert CalculationType.SUBTRACT.value == "Subtract"
        assert CalculationType.MULTIPLY.value == "Multiply"
        assert CalculationType.DIVIDE.value == "Divide"
    
    def test_calculation_type_from_string(self):
        """Test creating CalculationType from string."""
        assert CalculationType("Add") == CalculationType.ADD
        assert CalculationType("Subtract") == CalculationType.SUBTRACT
        assert CalculationType("Multiply") == CalculationType.MULTIPLY
        assert CalculationType("Divide") == CalculationType.DIVIDE


class TestCalculationCreate:
    """Test suite for CalculationCreate schema."""
    
    def test_valid_calculation_create_add(self):
        """Test valid calculation creation with Add type."""
        calc = CalculationCreate(a=10.5, b=5.2, type=CalculationType.ADD)
        assert calc.a == 10.5
        assert calc.b == 5.2
        assert calc.type == CalculationType.ADD
        assert calc.user_id is None
    
    def test_valid_calculation_create_with_user_id(self):
        """Test valid calculation creation with user_id."""
        calc = CalculationCreate(a=10.0, b=5.0, type=CalculationType.SUBTRACT, user_id=1)
        assert calc.a == 10.0
        assert calc.b == 5.0
        assert calc.type == CalculationType.SUBTRACT
        assert calc.user_id == 1
    
    def test_valid_calculation_create_all_types(self):
        """Test calculation creation with all operation types."""
        for calc_type in [CalculationType.ADD, CalculationType.SUBTRACT, 
                          CalculationType.MULTIPLY, CalculationType.DIVIDE]:
            calc = CalculationCreate(a=10.0, b=2.0, type=calc_type)
            assert calc.type == calc_type
    
    def test_divide_by_zero_validation(self):
        """Test that division by zero is rejected."""
        with pytest.raises(ValidationError) as exc_info:
            CalculationCreate(a=10.0, b=0.0, type=CalculationType.DIVIDE)
        
        errors = exc_info.value.errors()
        assert len(errors) > 0
        assert any("Division by zero" in str(error.get("msg", "")) for error in errors)
    
    def test_non_zero_divisor_allowed(self):
        """Test that non-zero divisor is allowed for division."""
        calc = CalculationCreate(a=10.0, b=2.0, type=CalculationType.DIVIDE)
        assert calc.b == 2.0
    
    def test_zero_divisor_allowed_for_non_division(self):
        """Test that zero is allowed as operand b for non-division operations."""
        calc_add = CalculationCreate(a=10.0, b=0.0, type=CalculationType.ADD)
        assert calc_add.b == 0.0
        
        calc_sub = CalculationCreate(a=10.0, b=0.0, type=CalculationType.SUBTRACT)
        assert calc_sub.b == 0.0
        
        calc_mult = CalculationCreate(a=10.0, b=0.0, type=CalculationType.MULTIPLY)
        assert calc_mult.b == 0.0
    
    def test_missing_required_fields(self):
        """Test that missing required fields raise ValidationError."""
        with pytest.raises(ValidationError):
            CalculationCreate(a=10.0)  # Missing b and type
        
        with pytest.raises(ValidationError):
            CalculationCreate(b=5.0, type=CalculationType.ADD)  # Missing a
        
        with pytest.raises(ValidationError):
            CalculationCreate(a=10.0, b=5.0)  # Missing type
    
    def test_invalid_type_string(self):
        """Test that invalid type string raises ValidationError."""
        with pytest.raises(ValidationError):
            CalculationCreate(a=10.0, b=5.0, type="Invalid")
    
    def test_negative_numbers(self):
        """Test calculation with negative numbers."""
        calc = CalculationCreate(a=-10.5, b=-5.2, type=CalculationType.ADD)
        assert calc.a == -10.5
        assert calc.b == -5.2
    
    def test_float_precision(self):
        """Test calculation with high precision floats."""
        calc = CalculationCreate(a=10.123456789, b=5.987654321, type=CalculationType.MULTIPLY)
        assert calc.a == pytest.approx(10.123456789)
        assert calc.b == pytest.approx(5.987654321)


class TestCalculationRead:
    """Test suite for CalculationRead schema."""
    
    def test_calculation_read_from_dict(self):
        """Test creating CalculationRead from dictionary."""
        from datetime import datetime
        
        calc_dict = {
            "id": 1,
            "a": 10.5,
            "b": 5.2,
            "type": "Add",
            "result": 15.7,
            "user_id": 1,
            "created_at": datetime.now()
        }
        
        calc = CalculationRead(**calc_dict)
        assert calc.id == 1
        assert calc.a == 10.5
        assert calc.b == 5.2
        assert calc.type == "Add"
        assert calc.result == 15.7
        assert calc.user_id == 1
    
    def test_calculation_read_without_user_id(self):
        """Test CalculationRead with None user_id."""
        from datetime import datetime
        
        calc_dict = {
            "id": 1,
            "a": 10.5,
            "b": 5.2,
            "type": "Subtract",
            "result": 5.3,
            "user_id": None,
            "created_at": datetime.now()
        }
        
        calc = CalculationRead(**calc_dict)
        assert calc.user_id is None


class TestCalculationUpdate:
    """Test suite for CalculationUpdate schema."""
    
    def test_update_all_fields(self):
        """Test updating all fields."""
        update = CalculationUpdate(a=20.0, b=10.0, type=CalculationType.MULTIPLY, user_id=2)
        assert update.a == 20.0
        assert update.b == 10.0
        assert update.type == CalculationType.MULTIPLY
        assert update.user_id == 2
    
    def test_update_partial_fields(self):
        """Test updating only some fields."""
        update = CalculationUpdate(a=30.0)
        assert update.a == 30.0
        assert update.b is None
        assert update.type is None
        assert update.user_id is None
    
    def test_update_empty(self):
        """Test creating update with no fields."""
        update = CalculationUpdate()
        assert update.a is None
        assert update.b is None
        assert update.type is None
        assert update.user_id is None
    
    def test_update_divide_by_zero_validation(self):
        """Test that updating to division by zero is rejected."""
        with pytest.raises(ValidationError) as exc_info:
            CalculationUpdate(b=0.0, type=CalculationType.DIVIDE)
        
        errors = exc_info.value.errors()
        assert len(errors) > 0
        assert any("Division by zero" in str(error.get("msg", "")) for error in errors)
    
    def test_update_zero_divisor_for_non_division(self):
        """Test that zero is allowed for non-division operations in update."""
        update = CalculationUpdate(b=0.0, type=CalculationType.ADD)
        assert update.b == 0.0
