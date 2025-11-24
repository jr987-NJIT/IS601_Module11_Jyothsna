"""Unit tests for password hashing and security utilities."""
import pytest
from app.utils import hash_password, verify_password


class TestPasswordHashing:
    """Test suite for password hashing functionality."""
    
    def test_hash_password_returns_string(self):
        """Test that hash_password returns a string."""
        password = "testpassword123"
        hashed = hash_password(password)
        assert isinstance(hashed, str)
        assert len(hashed) > 0
    
    def test_hash_password_different_each_time(self):
        """Test that hashing the same password twice produces different hashes (due to salt)."""
        password = "testpassword123"
        hash1 = hash_password(password)
        hash2 = hash_password(password)
        assert hash1 != hash2  # Bcrypt uses random salt
    
    def test_verify_password_correct(self):
        """Test that verify_password returns True for correct password."""
        password = "mysecretpassword"
        hashed = hash_password(password)
        assert verify_password(password, hashed) is True
    
    def test_verify_password_incorrect(self):
        """Test that verify_password returns False for incorrect password."""
        password = "mysecretpassword"
        wrong_password = "wrongpassword"
        hashed = hash_password(password)
        assert verify_password(wrong_password, hashed) is False
    
    def test_verify_password_empty_string(self):
        """Test that verify_password handles empty passwords correctly."""
        password = "mysecretpassword"
        hashed = hash_password(password)
        assert verify_password("", hashed) is False
    
    def test_hash_password_with_special_characters(self):
        """Test hashing passwords with special characters."""
        password = "P@ssw0rd!#$%^&*()"
        hashed = hash_password(password)
        assert verify_password(password, hashed) is True
    
    def test_hash_password_long_password(self):
        """Test hashing very long passwords."""
        password = "a" * 100
        hashed = hash_password(password)
        assert verify_password(password, hashed) is True
