"""Unit tests for calculation factory and operations."""
import pytest
from app.utils.calculation_factory import (
    CalculationFactory,
    AddOperation,
    SubtractOperation,
    MultiplyOperation,
    DivideOperation
)
from app.schemas.calculation import CalculationType


class TestOperations:
    """Test suite for individual operation classes."""
    
    def test_add_operation(self):
        """Test addition operation."""
        op = AddOperation()
        assert op.execute(5.0, 3.0) == 8.0
        assert op.execute(-5.0, 3.0) == -2.0
        assert op.execute(0.0, 0.0) == 0.0
        assert op.execute(10.5, 5.5) == 16.0
    
    def test_subtract_operation(self):
        """Test subtraction operation."""
        op = SubtractOperation()
        assert op.execute(5.0, 3.0) == 2.0
        assert op.execute(3.0, 5.0) == -2.0
        assert op.execute(0.0, 0.0) == 0.0
        assert op.execute(10.5, 5.5) == 5.0
    
    def test_multiply_operation(self):
        """Test multiplication operation."""
        op = MultiplyOperation()
        assert op.execute(5.0, 3.0) == 15.0
        assert op.execute(-5.0, 3.0) == -15.0
        assert op.execute(0.0, 5.0) == 0.0
        assert op.execute(2.5, 4.0) == 10.0
    
    def test_divide_operation(self):
        """Test division operation."""
        op = DivideOperation()
        assert op.execute(10.0, 2.0) == 5.0
        assert op.execute(15.0, 3.0) == 5.0
        assert op.execute(-10.0, 2.0) == -5.0
        assert op.execute(7.5, 2.5) == 3.0
    
    def test_divide_by_zero(self):
        """Test that division by zero raises ValueError."""
        op = DivideOperation()
        with pytest.raises(ValueError, match="Division by zero is not allowed"):
            op.execute(10.0, 0.0)


class TestCalculationFactory:
    """Test suite for CalculationFactory."""
    
    def test_create_add_operation(self):
        """Test factory creates AddOperation correctly."""
        op = CalculationFactory.create_operation(CalculationType.ADD)
        assert isinstance(op, AddOperation)
        assert op.execute(5.0, 3.0) == 8.0
    
    def test_create_subtract_operation(self):
        """Test factory creates SubtractOperation correctly."""
        op = CalculationFactory.create_operation(CalculationType.SUBTRACT)
        assert isinstance(op, SubtractOperation)
        assert op.execute(5.0, 3.0) == 2.0
    
    def test_create_multiply_operation(self):
        """Test factory creates MultiplyOperation correctly."""
        op = CalculationFactory.create_operation(CalculationType.MULTIPLY)
        assert isinstance(op, MultiplyOperation)
        assert op.execute(5.0, 3.0) == 15.0
    
    def test_create_divide_operation(self):
        """Test factory creates DivideOperation correctly."""
        op = CalculationFactory.create_operation(CalculationType.DIVIDE)
        assert isinstance(op, DivideOperation)
        assert op.execute(10.0, 2.0) == 5.0
    
    def test_calculate_add(self):
        """Test factory calculate method with addition."""
        result = CalculationFactory.calculate(CalculationType.ADD, 10.0, 5.0)
        assert result == 15.0
    
    def test_calculate_subtract(self):
        """Test factory calculate method with subtraction."""
        result = CalculationFactory.calculate(CalculationType.SUBTRACT, 10.0, 5.0)
        assert result == 5.0
    
    def test_calculate_multiply(self):
        """Test factory calculate method with multiplication."""
        result = CalculationFactory.calculate(CalculationType.MULTIPLY, 10.0, 5.0)
        assert result == 50.0
    
    def test_calculate_divide(self):
        """Test factory calculate method with division."""
        result = CalculationFactory.calculate(CalculationType.DIVIDE, 10.0, 5.0)
        assert result == 2.0
    
    def test_calculate_divide_by_zero(self):
        """Test factory handles division by zero."""
        with pytest.raises(ValueError, match="Division by zero is not allowed"):
            CalculationFactory.calculate(CalculationType.DIVIDE, 10.0, 0.0)
    
    def test_get_supported_operations(self):
        """Test getting list of supported operations."""
        operations = CalculationFactory.get_supported_operations()
        assert "Add" in operations
        assert "Subtract" in operations
        assert "Multiply" in operations
        assert "Divide" in operations
        assert len(operations) == 4
    
    def test_calculate_with_floats(self):
        """Test calculations with floating point numbers."""
        result = CalculationFactory.calculate(CalculationType.ADD, 10.5, 5.25)
        assert result == 15.75
        
        result = CalculationFactory.calculate(CalculationType.MULTIPLY, 2.5, 4.2)
        assert result == pytest.approx(10.5, rel=1e-9)
    
    def test_calculate_with_negative_numbers(self):
        """Test calculations with negative numbers."""
        result = CalculationFactory.calculate(CalculationType.ADD, -10.0, -5.0)
        assert result == -15.0
        
        result = CalculationFactory.calculate(CalculationType.MULTIPLY, -10.0, 5.0)
        assert result == -50.0
        
        result = CalculationFactory.calculate(CalculationType.DIVIDE, -10.0, 2.0)
        assert result == -5.0
