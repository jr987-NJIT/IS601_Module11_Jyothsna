# Secure User Management API with Calculation Model

A FastAPI application implementing secure user management with password hashing, PostgreSQL database integration, calculation model with factory pattern, comprehensive testing, and CI/CD pipeline.

## 🚀 Features

### Module 10 Features
- **Secure User Registration**: User accounts with hashed passwords using bcrypt
- **SQLAlchemy ORM**: Database models with unique constraints for username and email
- **Pydantic Validation**: Request/response validation with type safety
- **Comprehensive Testing**: Unit and integration tests with pytest
- **CI/CD Pipeline**: Automated testing and Docker image deployment via GitHub Actions
- **Docker Support**: Containerized application with Docker and Docker Compose
- **RESTful API**: FastAPI endpoints for user CRUD operations

### Module 11 Features (New)
- **Calculation Model**: SQLAlchemy model for storing mathematical operations (Add, Subtract, Multiply, Divide)
- **Factory Pattern**: Extensible calculation factory for operation handling
- **Calculation Schemas**: Pydantic validation with division-by-zero protection
- **User-Calculation Relationship**: Foreign key relationship with cascade deletion
- **Comprehensive Calculation Tests**: Unit and integration tests for calculations
- **Enhanced CI/CD**: Updated pipeline to test all calculation functionality

## 📋 Prerequisites

- Python 3.11+
- Docker and Docker Compose
- PostgreSQL (or use Docker Compose)
- Git

## 🛠️ Installation & Setup

### 1. Clone the Repository

```bash
git clone https://github.com/jr987-NJIT/IS601_Module10_Jyothsna.git
cd IS601_Module10_Jyothsna
```

### 2. Create Environment File

```bash
cp .env.example .env
```

Edit `.env` with your configuration:
```env
DATABASE_URL=postgresql://postgres:postgres@localhost:5432/userdb
SECRET_KEY=your-secret-key-here
ENVIRONMENT=development
```

### 3. Install Dependencies

```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
# Windows:
.\venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate

# Install requirements
pip install -r requirements.txt
```

## 🏃 Running the Application

### Option 1: Using Docker Compose (Recommended)

```bash
docker-compose up --build
```

The API will be available at `http://localhost:8000`

### Option 2: Local Development

```bash
# Start PostgreSQL (or use Docker)
docker run -d --name postgres \
  -e POSTGRES_USER=postgres \
  -e POSTGRES_PASSWORD=postgres \
  -e POSTGRES_DB=userdb \
  -p 5432:5432 \
  postgres:15-alpine

# Run the application
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

## 🧪 Running Tests

### Run All Tests

```bash
pytest
```

### Run Specific Test Categories

```bash
# Unit tests only (security, schemas, calculation factory, and calculation schemas)
pytest tests/test_security.py tests/test_schemas.py tests/test_calculation_factory.py tests/test_calculation_schemas.py -v

# Integration tests only (includes calculation database operations)
pytest tests/test_integration.py -v

# Run only calculation-related tests
pytest tests/test_calculation_factory.py tests/test_calculation_schemas.py -v
```

### Run Tests with Coverage

```bash
pip install pytest-cov
pytest --cov=app --cov-report=html --cov-report=term-missing
```

View coverage report by opening `htmlcov/index.html` in your browser.

### Test Categories

- **Unit Tests**: 
  - `test_security.py`: Password hashing and verification
  - `test_schemas.py`: User schema validation
  - `test_calculation_factory.py`: Calculation factory pattern and operations (Module 11)
  - `test_calculation_schemas.py`: Calculation schema validation with division by zero checks (Module 11)

- **Integration Tests**: `test_integration.py`
  - User creation with database constraints
  - Calculation model database operations with factory pattern (Module 11)
  - User-Calculation relationship and cascade deletion (Module 11)
  - Email uniqueness validation
  - Username uniqueness validation
  - API endpoint functionality
  - Password security in database

## 📚 API Documentation

Once the application is running, access the interactive API documentation:

- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

### API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | Root endpoint |
| GET | `/health` | Health check |
| POST | `/users/` | Create new user |
| GET | `/users/` | List all users |
| GET | `/users/{user_id}` | Get user by ID |
| GET | `/users/username/{username}` | Get user by username |
| DELETE | `/users/{user_id}` | Delete user |

### Example Usage

**Create a User:**
```bash
curl -X POST "http://localhost:8000/users/" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "johndoe",
    "email": "johndoe@example.com",
    "password": "securepassword123"
  }'
```

**Get All Users:**
```bash
curl "http://localhost:8000/users/"
```

## 📊 Calculation Model (Module 11)

The Calculation model stores mathematical operations with the following fields:
- `id`: Primary key
- `a`: First operand (float)
- `b`: Second operand (float)
- `type`: Operation type (Add, Subtract, Multiply, Divide)
- `result`: Computed result
- `user_id`: Optional foreign key to users table
- `created_at`: Timestamp

### Factory Pattern Implementation

The `CalculationFactory` implements the Factory design pattern:

```python
from app.utils import CalculationFactory
from app.schemas.calculation import CalculationType

# Execute calculation using factory
result = CalculationFactory.calculate(CalculationType.ADD, 10.5, 5.2)
print(result)  # 15.7

# Get supported operations
operations = CalculationFactory.get_supported_operations()
print(operations)  # ['Add', 'Subtract', 'Multiply', 'Divide']
```

### Pydantic Validation

The `CalculationCreate` schema includes validation:
- Division by zero is prevented
- Valid operation types enforced (Add, Subtract, Multiply, Divide)
- Type safety for operands

```python
from app.schemas import CalculationCreate, CalculationType

# Valid calculation
calc = CalculationCreate(a=10.0, b=5.0, type=CalculationType.DIVIDE)

# This will raise ValidationError
calc = CalculationCreate(a=10.0, b=0.0, type=CalculationType.DIVIDE)
```

## 🐳 Docker Hub

The Docker image is automatically built and pushed to Docker Hub via GitHub Actions.

**Docker Hub Repository**: Replace with your Docker Hub repository link

### Pull and Run the Image

```bash
# Pull the latest image
docker pull [your-dockerhub-username]/secure-user-api:latest

# Run the container
docker run -d \
  -p 8000:8000 \
  -e DATABASE_URL=postgresql://postgres:postgres@host.docker.internal:5432/userdb \
  [your-dockerhub-username]/secure-user-api:latest
```

## 🔄 CI/CD Pipeline

The project uses GitHub Actions for continuous integration and deployment:

### Workflow Steps

1. **Test Job**
   - Runs on every push and pull request
   - Sets up Python 3.11 environment
   - Spins up PostgreSQL test database
   - Runs unit tests (security, schemas, calculation factory, calculation schemas)
   - Runs integration tests (user and calculation database operations)
   - Generates coverage report
   - Uploads coverage to Codecov

2. **Build and Push Job** (main branch only)
   - Builds Docker image with latest code
   - Pushes to Docker Hub with tags:
     - `latest`
     - Git SHA
     - Semantic version (if tagged)
   - Uses caching for faster builds

### Setting Up CI/CD

Add the following secrets to your GitHub repository (Settings → Secrets → Actions):

- `DOCKER_USERNAME`: Your Docker Hub username
- `DOCKER_PASSWORD`: Your Docker Hub access token

## 🏗️ Project Structure

```
IS601_Module10_Jyothsna/
├── app/
│   ├── __init__.py
│   ├── main.py                      # FastAPI application
│   ├── database.py                  # Database configuration
│   ├── models/
│   │   ├── __init__.py              # User and Calculation models
│   │   ├── user.py                  # Model exports
│   │   └── calculation.py           # Calculation model (Module 11)
│   ├── schemas/
│   │   ├── __init__.py              # Pydantic schemas
│   │   ├── user.py                  # Schema exports
│   │   └── calculation.py           # Calculation schemas (Module 11)
│   └── utils/
│       ├── __init__.py              # Utilities exports
│       ├── security.py              # Password hashing
│       └── calculation_factory.py   # Factory pattern (Module 11)
├── tests/
│   ├── __init__.py
│   ├── test_security.py             # Unit tests for security
│   ├── test_schemas.py              # Unit tests for user schemas
│   ├── test_calculation_factory.py  # Unit tests for factory (Module 11)
│   ├── test_calculation_schemas.py  # Unit tests for calc schemas (Module 11)
│   └── test_integration.py          # Integration tests (includes calculations)
├── .github/
│   └── workflows/
│       └── ci-cd.yml                # GitHub Actions workflow
├── .env.example                     # Environment variables template
├── .gitignore
├── docker-compose.yml               # Docker Compose configuration
├── Dockerfile                       # Docker image definition
├── pytest.ini                       # Pytest configuration
├── requirements.txt                 # Python dependencies
├── README.md
└── REFLECTION.md                    # Module 11 reflection
```

## 🔒 Security Features

- **Password Hashing**: All passwords are hashed using bcrypt before storage
- **No Plain Text**: Passwords never stored or returned in plain text
- **Unique Constraints**: Database-level uniqueness for usernames and emails
- **Input Validation**: Pydantic schemas validate all input data
- **SQL Injection Protection**: SQLAlchemy ORM prevents SQL injection
- **Environment Variables**: Sensitive data stored in environment variables

## 🧩 Technologies Used

- **FastAPI**: Modern, fast web framework for building APIs
- **SQLAlchemy**: SQL toolkit and ORM
- **PostgreSQL**: Relational database
- **Pydantic**: Data validation using Python type hints
- **Passlib**: Password hashing library with bcrypt
- **Pytest**: Testing framework
- **Docker**: Containerization
- **GitHub Actions**: CI/CD automation
- **Trivy**: Security vulnerability scanning

## 📝 Testing Strategy

### Unit Tests
- Test individual functions in isolation
- Mock external dependencies
- Focus on business logic and validation

### Integration Tests
- Test full request/response cycle
- Use real database (SQLite for tests)
- Verify database constraints
- Test API endpoints end-to-end

## 🎓 Learning Outcomes Addressed

### Module 10
- **CLO3**: Automated testing with pytest
- **CLO4**: GitHub Actions CI/CD pipeline
- **CLO9**: Docker containerization
- **CLO11**: SQL database integration with SQLAlchemy
- **CLO12**: JSON serialization with Pydantic
- **CLO13**: Secure authentication with password hashing

### Module 11 (New)
- **CLO3**: Extended automated testing for calculation models
- **CLO4**: Enhanced CI/CD pipeline with calculation tests
- **CLO9**: Updated Docker image with calculation functionality
- **CLO11**: Calculation model with foreign key relationships
- **CLO12**: Calculation schema validation and serialization
- **Design Patterns**: Factory pattern implementation for extensibility

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License.

## 👤 Author

Jyothsna Reddy
- GitHub: [@jr987-NJIT](https://github.com/jr987-NJIT)
- Repository: [IS601_Module10_Jyothsna](https://github.com/jr987-NJIT/IS601_Module10_Jyothsna)

## 🙏 Acknowledgments

- Course: IS601 - Web Systems Development
- Institution: NJIT
- Module 10: Secure User Authentication
- Module 11: Calculation Model with Factory Pattern

---

**Note**: Module 11 extends Module 10 by adding a Calculation model with factory pattern implementation. BREAD (Browse, Read, Edit, Add, Delete) API endpoints for calculations will be implemented in Module 12.

---

**Note**: Remember to update the Docker Hub repository URL and add your Docker Hub credentials to GitHub secrets before pushing to the main branch.
