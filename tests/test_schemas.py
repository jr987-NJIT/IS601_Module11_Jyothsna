"""Unit tests for Pydantic schemas."""
import pytest
from datetime import datetime
from pydantic import ValidationError
from app.schemas import UserCreate, UserRead


class TestUserCreateSchema:
    """Test suite for UserCreate schema validation."""
    
    def test_valid_user_create(self):
        """Test creating a valid UserCreate schema."""
        user_data = {
            "username": "testuser",
            "email": "test@example.com",
            "password": "securepass123"
        }
        user = UserCreate(**user_data)
        assert user.username == "testuser"
        assert user.email == "test@example.com"
        assert user.password == "securepass123"
    
    def test_username_too_short(self):
        """Test that username must be at least 3 characters."""
        user_data = {
            "username": "ab",
            "email": "test@example.com",
            "password": "securepass123"
        }
        with pytest.raises(ValidationError) as exc_info:
            UserCreate(**user_data)
        assert "username" in str(exc_info.value)
    
    def test_username_too_long(self):
        """Test that username cannot exceed 50 characters."""
        user_data = {
            "username": "a" * 51,
            "email": "test@example.com",
            "password": "securepass123"
        }
        with pytest.raises(ValidationError) as exc_info:
            UserCreate(**user_data)
        assert "username" in str(exc_info.value)
    
    def test_invalid_email(self):
        """Test that email must be valid format."""
        user_data = {
            "username": "testuser",
            "email": "notanemail",
            "password": "securepass123"
        }
        with pytest.raises(ValidationError) as exc_info:
            UserCreate(**user_data)
        assert "email" in str(exc_info.value)
    
    def test_password_too_short(self):
        """Test that password must be at least 8 characters."""
        user_data = {
            "username": "testuser",
            "email": "test@example.com",
            "password": "short"
        }
        with pytest.raises(ValidationError) as exc_info:
            UserCreate(**user_data)
        assert "password" in str(exc_info.value)
    
    def test_missing_required_fields(self):
        """Test that all required fields must be provided."""
        with pytest.raises(ValidationError):
            UserCreate(username="testuser")
    
    def test_email_with_special_characters(self):
        """Test email validation with special characters."""
        user_data = {
            "username": "testuser",
            "email": "test+tag@example.co.uk",
            "password": "securepass123"
        }
        user = UserCreate(**user_data)
        assert user.email == "test+tag@example.co.uk"


class TestUserReadSchema:
    """Test suite for UserRead schema."""
    
    def test_user_read_from_dict(self):
        """Test creating UserRead from dictionary."""
        user_data = {
            "id": 1,
            "username": "testuser",
            "email": "test@example.com",
            "created_at": datetime.now()
        }
        user = UserRead(**user_data)
        assert user.id == 1
        assert user.username == "testuser"
        assert user.email == "test@example.com"
        assert isinstance(user.created_at, datetime)
    
    def test_user_read_does_not_include_password(self):
        """Test that UserRead schema doesn't have password field."""
        user_data = {
            "id": 1,
            "username": "testuser",
            "email": "test@example.com",
            "created_at": datetime.now()
        }
        user = UserRead(**user_data)
        assert not hasattr(user, 'password')
        assert not hasattr(user, 'password_hash')
