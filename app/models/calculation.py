"""SQLAlchemy Calculation model for storing mathematical operations."""
from sqlalchemy import Column, Integer, Float, String, DateTime, ForeignKey
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from app.database import Base


class Calculation(Base):
    """
    Calculation model for storing mathematical operations and their results.
    
    Attributes:
        id: Primary key
        a: First operand (float)
        b: Second operand (float)
        type: Operation type (Add, Subtract, Multiply, Divide)
        result: Computed result of the operation
        user_id: Foreign key to users table (optional)
        created_at: Timestamp of calculation creation
    """
    __tablename__ = "calculations"

    id = Column(Integer, primary_key=True, index=True)
    a = Column(Float, nullable=False)
    b = Column(Float, nullable=False)
    type = Column(String(20), nullable=False)
    result = Column(Float, nullable=False)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    # Relationship to User model
    user = relationship("User", back_populates="calculations")

    def __repr__(self):
        return f"<Calculation(id={self.id}, type='{self.type}', a={self.a}, b={self.b}, result={self.result})>"
