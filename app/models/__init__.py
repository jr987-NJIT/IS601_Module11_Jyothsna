"""SQLAlchemy User model with secure password storage."""
from sqlalchemy import Column, Integer, String, DateTime
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from app.database import Base


class User(Base):
    """
    User model for storing user account information.
    
    Attributes:
        id: Primary key
        username: Unique username for the user
        email: Unique email address
        password_hash: Hashed password (never store plain text passwords)
        created_at: Timestamp of user creation
    """
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, nullable=False, index=True)
    email = Column(String(100), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    # Relationship to Calculation model
    calculations = relationship("Calculation", back_populates="user", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<User(id={self.id}, username='{self.username}', email='{self.email}')>"


# Import Calculation model after User to avoid circular imports
from app.models.calculation import Calculation  # noqa: E402

__all__ = ["User", "Calculation"]
