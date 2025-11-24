"""Integration tests for database operations and API endpoints."""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.main import app
from app.database import Base, get_db
from app.models import User

# Create test database
SQLALCHEMY_DATABASE_URL = "sqlite:///./test.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def override_get_db():
    """Override database dependency for testing."""
    try:
        db = TestingSessionLocal()
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db
client = TestClient(app)


@pytest.fixture(autouse=True)
def setup_database():
    """Create and drop database tables for each test."""
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


class TestRootEndpoints:
    """Test suite for root and health endpoints."""
    
    def test_read_root(self):
        """Test root endpoint returns correct message."""
        response = client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert "message" in data
        assert "version" in data
    
    def test_health_check(self):
        """Test health check endpoint."""
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json() == {"status": "healthy"}


class TestUserCreation:
    """Test suite for user creation endpoint."""
    
    def test_create_user_success(self):
        """Test successful user creation."""
        user_data = {
            "username": "testuser",
            "email": "test@example.com",
            "password": "securepass123"
        }
        response = client.post("/users/", json=user_data)
        assert response.status_code == 201
        data = response.json()
        assert data["username"] == "testuser"
        assert data["email"] == "test@example.com"
        assert "password" not in data
        assert "password_hash" not in data
        assert "id" in data
        assert "created_at" in data
    
    def test_create_user_duplicate_username(self):
        """Test that duplicate username is rejected."""
        user_data = {
            "username": "testuser",
            "email": "test1@example.com",
            "password": "securepass123"
        }
        # Create first user
        response1 = client.post("/users/", json=user_data)
        assert response1.status_code == 201
        
        # Try to create user with same username
        user_data2 = {
            "username": "testuser",
            "email": "test2@example.com",
            "password": "securepass123"
        }
        response2 = client.post("/users/", json=user_data2)
        assert response2.status_code == 400
        assert "Username already registered" in response2.json()["detail"]
    
    def test_create_user_duplicate_email(self):
        """Test that duplicate email is rejected."""
        user_data = {
            "username": "testuser1",
            "email": "test@example.com",
            "password": "securepass123"
        }
        # Create first user
        response1 = client.post("/users/", json=user_data)
        assert response1.status_code == 201
        
        # Try to create user with same email
        user_data2 = {
            "username": "testuser2",
            "email": "test@example.com",
            "password": "securepass123"
        }
        response2 = client.post("/users/", json=user_data2)
        assert response2.status_code == 400
        assert "Email already registered" in response2.json()["detail"]
    
    def test_create_user_invalid_email(self):
        """Test that invalid email format is rejected."""
        user_data = {
            "username": "testuser",
            "email": "notanemail",
            "password": "securepass123"
        }
        response = client.post("/users/", json=user_data)
        assert response.status_code == 422  # Validation error
    
    def test_create_user_short_password(self):
        """Test that short password is rejected."""
        user_data = {
            "username": "testuser",
            "email": "test@example.com",
            "password": "short"
        }
        response = client.post("/users/", json=user_data)
        assert response.status_code == 422  # Validation error
    
    def test_create_user_short_username(self):
        """Test that short username is rejected."""
        user_data = {
            "username": "ab",
            "email": "test@example.com",
            "password": "securepass123"
        }
        response = client.post("/users/", json=user_data)
        assert response.status_code == 422  # Validation error


class TestUserRetrieval:
    """Test suite for user retrieval endpoints."""
    
    def test_get_users_empty(self):
        """Test getting users when database is empty."""
        response = client.get("/users/")
        assert response.status_code == 200
        assert response.json() == []
    
    def test_get_users_with_data(self):
        """Test getting users when database has users."""
        # Create test users
        user1 = {"username": "user1", "email": "user1@example.com", "password": "pass123456"}
        user2 = {"username": "user2", "email": "user2@example.com", "password": "pass123456"}
        client.post("/users/", json=user1)
        client.post("/users/", json=user2)
        
        response = client.get("/users/")
        assert response.status_code == 200
        users = response.json()
        assert len(users) == 2
        assert users[0]["username"] == "user1"
        assert users[1]["username"] == "user2"
    
    def test_get_user_by_id(self):
        """Test getting a specific user by ID."""
        # Create a user
        user_data = {"username": "testuser", "email": "test@example.com", "password": "pass123456"}
        create_response = client.post("/users/", json=user_data)
        user_id = create_response.json()["id"]
        
        # Retrieve user by ID
        response = client.get(f"/users/{user_id}")
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == user_id
        assert data["username"] == "testuser"
    
    def test_get_user_by_id_not_found(self):
        """Test getting a non-existent user by ID."""
        response = client.get("/users/9999")
        assert response.status_code == 404
        assert "not found" in response.json()["detail"].lower()
    
    def test_get_user_by_username(self):
        """Test getting a user by username."""
        # Create a user
        user_data = {"username": "testuser", "email": "test@example.com", "password": "pass123456"}
        client.post("/users/", json=user_data)
        
        # Retrieve user by username
        response = client.get("/users/username/testuser")
        assert response.status_code == 200
        data = response.json()
        assert data["username"] == "testuser"
    
    def test_get_user_by_username_not_found(self):
        """Test getting a non-existent user by username."""
        response = client.get("/users/username/nonexistent")
        assert response.status_code == 404


class TestUserDeletion:
    """Test suite for user deletion endpoint."""
    
    def test_delete_user_success(self):
        """Test successful user deletion."""
        # Create a user
        user_data = {"username": "testuser", "email": "test@example.com", "password": "pass123456"}
        create_response = client.post("/users/", json=user_data)
        user_id = create_response.json()["id"]
        
        # Delete user
        response = client.delete(f"/users/{user_id}")
        assert response.status_code == 204
        
        # Verify user is deleted
        get_response = client.get(f"/users/{user_id}")
        assert get_response.status_code == 404
    
    def test_delete_user_not_found(self):
        """Test deleting a non-existent user."""
        response = client.delete("/users/9999")
        assert response.status_code == 404


class TestPasswordSecurity:
    """Test suite for password security in database."""
    
    def test_password_is_hashed(self):
        """Test that passwords are hashed in the database."""
        user_data = {
            "username": "testuser",
            "email": "test@example.com",
            "password": "plainpassword123"
        }
        response = client.post("/users/", json=user_data)
        assert response.status_code == 201
        
        # Check database directly
        db = TestingSessionLocal()
        user = db.query(User).filter(User.username == "testuser").first()
        assert user is not None
        assert user.password_hash != "plainpassword123"
        assert user.password_hash.startswith("$2b$")  # Bcrypt hash format
        db.close()
    
    def test_password_not_returned_in_response(self):
        """Test that password is never returned in API responses."""
        user_data = {
            "username": "testuser",
            "email": "test@example.com",
            "password": "plainpassword123"
        }
        response = client.post("/users/", json=user_data)
        data = response.json()
        
        assert "password" not in data
        assert "password_hash" not in data


class TestCalculationDatabaseOperations:
    """Test suite for calculation database operations."""
    
    def test_create_calculation_in_database(self):
        """Test creating a calculation record in the database."""
        from app.models import Calculation
        from app.schemas.calculation import CalculationType
        from app.utils.calculation_factory import CalculationFactory
        
        # Create calculation
        calc_type = CalculationType.ADD
        a, b = 10.5, 5.2
        result = CalculationFactory.calculate(calc_type, a, b)
        
        db = TestingSessionLocal()
        db_calc = Calculation(
            a=a,
            b=b,
            type=calc_type.value,
            result=result
        )
        db.add(db_calc)
        db.commit()
        db.refresh(db_calc)
        
        # Verify stored data
        assert db_calc.id is not None
        assert db_calc.a == 10.5
        assert db_calc.b == 5.2
        assert db_calc.type == "Add"
        assert db_calc.result == 15.7
        assert db_calc.user_id is None
        assert db_calc.created_at is not None
        db.close()
    
    def test_create_calculation_with_user_id(self):
        """Test creating a calculation with user_id foreign key."""
        from app.models import User, Calculation
        from app.schemas.calculation import CalculationType
        from app.utils.calculation_factory import CalculationFactory
        from app.utils import hash_password
        
        db = TestingSessionLocal()
        
        # Create user first
        user = User(
            username="testuser",
            email="test@example.com",
            password_hash=hash_password("password123")
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        
        # Create calculation linked to user
        calc_type = CalculationType.MULTIPLY
        a, b = 6.0, 7.0
        result = CalculationFactory.calculate(calc_type, a, b)
        
        db_calc = Calculation(
            a=a,
            b=b,
            type=calc_type.value,
            result=result,
            user_id=user.id
        )
        db.add(db_calc)
        db.commit()
        db.refresh(db_calc)
        
        # Verify stored data
        assert db_calc.user_id == user.id
        assert db_calc.result == 42.0
        
        # Test relationship
        assert user.calculations[0].id == db_calc.id
        db.close()
    
    def test_retrieve_calculation_from_database(self):
        """Test retrieving a calculation from the database."""
        from app.models import Calculation
        from app.schemas.calculation import CalculationType
        from app.utils.calculation_factory import CalculationFactory
        
        db = TestingSessionLocal()
        
        # Create calculation
        calc_type = CalculationType.SUBTRACT
        a, b = 20.0, 8.0
        result = CalculationFactory.calculate(calc_type, a, b)
        
        db_calc = Calculation(
            a=a,
            b=b,
            type=calc_type.value,
            result=result
        )
        db.add(db_calc)
        db.commit()
        calc_id = db_calc.id
        
        # Retrieve calculation
        retrieved_calc = db.query(Calculation).filter(Calculation.id == calc_id).first()
        
        assert retrieved_calc is not None
        assert retrieved_calc.a == 20.0
        assert retrieved_calc.b == 8.0
        assert retrieved_calc.type == "Subtract"
        assert retrieved_calc.result == 12.0
        db.close()
    
    def test_calculation_all_operation_types(self):
        """Test storing all calculation operation types."""
        from app.models import Calculation
        from app.schemas.calculation import CalculationType
        from app.utils.calculation_factory import CalculationFactory
        
        db = TestingSessionLocal()
        
        test_cases = [
            (CalculationType.ADD, 10.0, 5.0, 15.0),
            (CalculationType.SUBTRACT, 10.0, 5.0, 5.0),
            (CalculationType.MULTIPLY, 10.0, 5.0, 50.0),
            (CalculationType.DIVIDE, 10.0, 5.0, 2.0),
        ]
        
        for calc_type, a, b, expected_result in test_cases:
            result = CalculationFactory.calculate(calc_type, a, b)
            assert result == expected_result
            
            db_calc = Calculation(
                a=a,
                b=b,
                type=calc_type.value,
                result=result
            )
            db.add(db_calc)
            db.commit()
            db.refresh(db_calc)
            
            assert db_calc.type == calc_type.value
            assert db_calc.result == expected_result
        
        # Verify all calculations are stored
        all_calcs = db.query(Calculation).all()
        assert len(all_calcs) == 4
        db.close()
    
    def test_division_by_zero_error(self):
        """Test that division by zero raises an error."""
        from app.schemas.calculation import CalculationType
        from app.utils.calculation_factory import CalculationFactory
        
        with pytest.raises(ValueError, match="Division by zero is not allowed"):
            CalculationFactory.calculate(CalculationType.DIVIDE, 10.0, 0.0)
    
    def test_invalid_calculation_type(self):
        """Test handling of invalid calculation type in database."""
        from app.models import Calculation
        
        db = TestingSessionLocal()
        
        # Create calculation with invalid type (stored as string, no enum validation at DB level)
        db_calc = Calculation(
            a=10.0,
            b=5.0,
            type="InvalidType",
            result=0.0
        )
        db.add(db_calc)
        db.commit()
        
        # Should be able to store, but application logic should validate
        assert db_calc.type == "InvalidType"
        db.close()
    
    def test_cascade_delete_calculations_with_user(self):
        """Test that calculations are deleted when user is deleted."""
        from app.models import User, Calculation
        from app.utils import hash_password
        
        db = TestingSessionLocal()
        
        # Create user
        user = User(
            username="testuser",
            email="test@example.com",
            password_hash=hash_password("password123")
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        
        # Create calculations for user
        for i in range(3):
            calc = Calculation(
                a=float(i),
                b=1.0,
                type="Add",
                result=float(i + 1),
                user_id=user.id
            )
            db.add(calc)
        db.commit()
        
        # Verify calculations exist
        user_calcs = db.query(Calculation).filter(Calculation.user_id == user.id).all()
        assert len(user_calcs) == 3
        
        # Delete user
        db.delete(user)
        db.commit()
        
        # Verify calculations are deleted (cascade)
        remaining_calcs = db.query(Calculation).filter(Calculation.user_id == user.id).all()
        assert len(remaining_calcs) == 0
        db.close()
    
    def test_calculation_with_large_numbers(self):
        """Test calculations with large numbers."""
        from app.models import Calculation
        from app.schemas.calculation import CalculationType
        from app.utils.calculation_factory import CalculationFactory
        
        db = TestingSessionLocal()
        
        a, b = 1e10, 2e10
        calc_type = CalculationType.ADD
        result = CalculationFactory.calculate(calc_type, a, b)
        
        db_calc = Calculation(
            a=a,
            b=b,
            type=calc_type.value,
            result=result
        )
        db.add(db_calc)
        db.commit()
        db.refresh(db_calc)
        
        assert db_calc.result == 3e10
        db.close()
    
    def test_calculation_with_negative_result(self):
        """Test calculation that produces negative result."""
        from app.models import Calculation
        from app.schemas.calculation import CalculationType
        from app.utils.calculation_factory import CalculationFactory
        
        db = TestingSessionLocal()
        
        a, b = 5.0, 10.0
        calc_type = CalculationType.SUBTRACT
        result = CalculationFactory.calculate(calc_type, a, b)
        
        db_calc = Calculation(
            a=a,
            b=b,
            type=calc_type.value,
            result=result
        )
        db.add(db_calc)
        db.commit()
        db.refresh(db_calc)
        
        assert db_calc.result == -5.0
        db.close()
