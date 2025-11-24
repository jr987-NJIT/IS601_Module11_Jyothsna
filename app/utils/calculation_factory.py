"""Factory pattern for creating and executing mathematical calculations."""
from abc import ABC, abstractmethod
from typing import Dict, Type
from app.schemas.calculation import CalculationType


class Operation(ABC):
    """Abstract base class for mathematical operations."""
    
    @abstractmethod
    def execute(self, a: float, b: float) -> float:
        """
        Execute the mathematical operation.
        
        Args:
            a: First operand
            b: Second operand
            
        Returns:
            Result of the operation
        """
        pass


class AddOperation(Operation):
    """Addition operation."""
    
    def execute(self, a: float, b: float) -> float:
        """Add two numbers."""
        return a + b


class SubtractOperation(Operation):
    """Subtraction operation."""
    
    def execute(self, a: float, b: float) -> float:
        """Subtract b from a."""
        return a - b


class MultiplyOperation(Operation):
    """Multiplication operation."""
    
    def execute(self, a: float, b: float) -> float:
        """Multiply two numbers."""
        return a * b


class DivideOperation(Operation):
    """Division operation."""
    
    def execute(self, a: float, b: float) -> float:
        """
        Divide a by b.
        
        Raises:
            ValueError: If b is zero
        """
        if b == 0:
            raise ValueError("Division by zero is not allowed")
        return a / b


class CalculationFactory:
    """
    Factory class for creating and executing calculation operations.
    
    This implements the Factory pattern to instantiate the correct
    operation class based on the calculation type.
    """
    
    # Registry mapping calculation types to operation classes
    _operations: Dict[CalculationType, Type[Operation]] = {
        CalculationType.ADD: AddOperation,
        CalculationType.SUBTRACT: SubtractOperation,
        CalculationType.MULTIPLY: MultiplyOperation,
        CalculationType.DIVIDE: DivideOperation,
    }
    
    @classmethod
    def create_operation(cls, calc_type: CalculationType) -> Operation:
        """
        Create an operation instance based on the calculation type.
        
        Args:
            calc_type: Type of calculation operation
            
        Returns:
            Instance of the appropriate operation class
            
        Raises:
            ValueError: If calculation type is not supported
        """
        operation_class = cls._operations.get(calc_type)
        if operation_class is None:
            raise ValueError(f"Unsupported calculation type: {calc_type}")
        return operation_class()
    
    @classmethod
    def calculate(cls, calc_type: CalculationType, a: float, b: float) -> float:
        """
        Execute a calculation using the factory pattern.
        
        Args:
            calc_type: Type of calculation operation
            a: First operand
            b: Second operand
            
        Returns:
            Result of the calculation
            
        Raises:
            ValueError: If calculation type is not supported or division by zero
        """
        operation = cls.create_operation(calc_type)
        return operation.execute(a, b)
    
    @classmethod
    def get_supported_operations(cls) -> list[str]:
        """
        Get a list of supported operation types.
        
        Returns:
            List of supported calculation type names
        """
        return [calc_type.value for calc_type in cls._operations.keys()]
