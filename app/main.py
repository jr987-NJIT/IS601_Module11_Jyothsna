"""FastAPI application with user management endpoints."""
from fastapi import FastAPI, Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from typing import List

from app.database import get_db, init_db
from app.models import User
from app.schemas import UserCreate, UserRead
from app.utils import hash_password

# Create FastAPI application
app = FastAPI(
    title="Secure User Management API",
    description="A secure FastAPI application with user registration and authentication",
    version="1.0.0"
)


@app.on_event("startup")
def on_startup():
    """Initialize database on application startup."""
    init_db()


@app.get("/", tags=["Root"])
def read_root():
    """Root endpoint returning API information."""
    return {
        "message": "Welcome to Secure User Management API",
        "version": "1.0.0",
        "docs": "/docs"
    }


@app.get("/health", tags=["Health"])
def health_check():
    """Health check endpoint."""
    return {"status": "healthy"}


@app.post("/users/", response_model=UserRead, status_code=status.HTTP_201_CREATED, tags=["Users"])
def create_user(user: UserCreate, db: Session = Depends(get_db)):
    """
    Create a new user account.
    
    Args:
        user: User creation data (username, email, password)
        db: Database session
        
    Returns:
        Created user information (without password)
        
    Raises:
        HTTPException: If username or email already exists
    """
    # Check if username already exists
    existing_user = db.query(User).filter(User.username == user.username).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered"
        )
    
    # Check if email already exists
    existing_email = db.query(User).filter(User.email == user.email).first()
    if existing_email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )
    
    # Hash the password
    hashed_password = hash_password(user.password)
    
    # Create new user
    db_user = User(
        username=user.username,
        email=user.email,
        password_hash=hashed_password
    )
    
    try:
        db.add(db_user)
        db.commit()
        db.refresh(db_user)
        return db_user
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User could not be created due to a database constraint"
        )


@app.get("/users/", response_model=List[UserRead], tags=["Users"])
def get_users(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    """
    Retrieve a list of users.
    
    Args:
        skip: Number of records to skip (for pagination)
        limit: Maximum number of records to return
        db: Database session
        
    Returns:
        List of users
    """
    users = db.query(User).offset(skip).limit(limit).all()
    return users


@app.get("/users/{user_id}", response_model=UserRead, tags=["Users"])
def get_user(user_id: int, db: Session = Depends(get_db)):
    """
    Retrieve a specific user by ID.
    
    Args:
        user_id: User ID to retrieve
        db: Database session
        
    Returns:
        User information
        
    Raises:
        HTTPException: If user not found
    """
    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    return user


@app.get("/users/username/{username}", response_model=UserRead, tags=["Users"])
def get_user_by_username(username: str, db: Session = Depends(get_db)):
    """
    Retrieve a specific user by username.
    
    Args:
        username: Username to search for
        db: Database session
        
    Returns:
        User information
        
    Raises:
        HTTPException: If user not found
    """
    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    return user


@app.delete("/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT, tags=["Users"])
def delete_user(user_id: int, db: Session = Depends(get_db)):
    """
    Delete a user by ID.
    
    Args:
        user_id: User ID to delete
        db: Database session
        
    Raises:
        HTTPException: If user not found
    """
    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    db.delete(user)
    db.commit()
    return None
