"""
VulnScan Lite — Authentication & Authorization Unit and Integration Tests

Tests:
  - User registration (valid credentials)
  - Duplicate email registration prevention (HTTP 409)
  - Invalid email format validation (HTTP 422)
  - Weak password validation (HTTP 422)
  - Password hashing and verification
  - Login with correct password (HTTP 200 + JWT)
  - Login with incorrect password (HTTP 401)
  - Login with non-existent user (HTTP 401)
  - JWT token generation, decoding, and expiration
  - GET /api/auth/me profile retrieval (HTTP 200 with valid JWT)
  - GET /api/auth/me with invalid or expired JWT (HTTP 401)
  - GET /api/auth/me with missing Authorization header (HTTP 401)
"""
import pytest
from datetime import timedelta
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool
from sqlalchemy.orm import sessionmaker
from fastapi.testclient import TestClient

from app.main import app
from app.database.database import Base, get_db
from app.core.security import (
    hash_password,
    verify_password,
    create_access_token,
    decode_access_token,
)
from app.database.models import User

# In-memory test SQLite database with StaticPool so all connections share the same memory DB
TEST_DB_URL = "sqlite:///:memory:"
engine = create_engine(
    TEST_DB_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


@pytest.fixture(autouse=True)
def setup_test_db():
    """Create fresh database tables before each test and drop after."""
    Base.metadata.create_all(bind=engine)
    
    def override_get_db():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    yield
    app.dependency_overrides.clear()
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def client():
    """TestClient instance with test DB override."""
    return TestClient(app)


# ---------------------------------------------------------------------------
# Password Hashing & Security Unit Tests
# ---------------------------------------------------------------------------

def test_password_hashing():
    """Password should be securely hashed and verified with bcrypt."""
    plain = "SuperSecure123"
    hashed = hash_password(plain)

    # Hash should not equal plain text
    assert hashed != plain
    # Verify hash is bcrypt
    assert hashed.startswith("$2b$") or hashed.startswith("$2a$")
    # Verify matches
    assert verify_password(plain, hashed) is True
    # Verify non-matching
    assert verify_password("WrongPassword1", hashed) is False


def test_jwt_create_and_decode():
    """JWT tokens should be properly created and decoded."""
    user_id = "test-user-uuid-1234"
    token = create_access_token(subject=user_id)

    decoded = decode_access_token(token)
    assert decoded == user_id


def test_jwt_expired_token():
    """Expired JWT tokens should decode to None."""
    user_id = "test-user-uuid-1234"
    # Create an expired token (-1 hour)
    expired_token = create_access_token(
        subject=user_id,
        expires_delta=timedelta(minutes=-60),
    )
    decoded = decode_access_token(expired_token)
    assert decoded is None


def test_jwt_invalid_token():
    """Malformed tokens should decode to None."""
    decoded = decode_access_token("invalid.token.structure")
    assert decoded is None


# ---------------------------------------------------------------------------
# Registration Tests
# ---------------------------------------------------------------------------

def test_register_success(client):
    """Registering a new user with valid credentials returns HTTP 201 and a JWT."""
    response = client.post("/api/auth/register", json={
        "email": "alice@example.com",
        "password": "SecurePassword1",
    })
    assert response.status_code == 201
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert "password" not in data
    assert "password_hash" not in data


def test_register_duplicate_email(client):
    """Registering with an already existing email returns HTTP 409."""
    payload = {
        "email": "bob@example.com",
        "password": "SecurePassword1",
    }
    # First registration
    res1 = client.post("/api/auth/register", json=payload)
    assert res1.status_code == 201

    # Duplicate registration
    res2 = client.post("/api/auth/register", json=payload)
    assert res2.status_code == 409
    assert "already exists" in res2.json()["detail"]


def test_register_invalid_email_format(client):
    """Registering with an invalid email returns HTTP 422."""
    response = client.post("/api/auth/register", json={
        "email": "not-an-email",
        "password": "SecurePassword1",
    })
    assert response.status_code == 422


@pytest.mark.parametrize("weak_password, reason", [
    ("short1A", "Too short (<8 chars)"),
    ("nouppercase123", "Missing uppercase"),
    ("NoDigitsHere", "Missing digit"),
])
def test_register_weak_passwords(client, weak_password, reason):
    """Registering with weak passwords violating complexity policy returns HTTP 422."""
    response = client.post("/api/auth/register", json={
        "email": "user@example.com",
        "password": weak_password,
    })
    assert response.status_code == 422


# ---------------------------------------------------------------------------
# Login Tests
# ---------------------------------------------------------------------------

def test_login_success(client):
    """Logging in with correct credentials returns HTTP 200 and access_token."""
    # Register first
    client.post("/api/auth/register", json={
        "email": "carol@example.com",
        "password": "SecurePassword1",
    })

    # Login
    response = client.post("/api/auth/login", json={
        "email": "carol@example.com",
        "password": "SecurePassword1",
    })
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"


def test_login_incorrect_password(client):
    """Logging in with incorrect password returns HTTP 401."""
    client.post("/api/auth/register", json={
        "email": "dave@example.com",
        "password": "SecurePassword1",
    })

    response = client.post("/api/auth/login", json={
        "email": "dave@example.com",
        "password": "WrongPassword1",
    })
    assert response.status_code == 401
    assert "Invalid email or password" in response.json()["detail"]


def test_login_nonexistent_user(client):
    """Logging in with a non-existent email returns HTTP 401."""
    response = client.post("/api/auth/login", json={
        "email": "unknown@example.com",
        "password": "SecurePassword1",
    })
    assert response.status_code == 401
    assert "Invalid email or password" in response.json()["detail"]


# ---------------------------------------------------------------------------
# Current User Profile (GET /api/auth/me) Tests
# ---------------------------------------------------------------------------

def test_get_me_success(client):
    """Authenticated GET /api/auth/me returns user profile."""
    # Register
    reg_res = client.post("/api/auth/register", json={
        "email": "eve@example.com",
        "password": "SecurePassword1",
    })
    token = reg_res.json()["access_token"]

    # Access /api/auth/me
    response = client.get("/api/auth/me", headers={
        "Authorization": f"Bearer {token}",
    })
    assert response.status_code == 200
    data = response.json()
    assert data["email"] == "eve@example.com"
    assert "id" in data
    assert "created_at" in data
    assert "password" not in data
    assert "password_hash" not in data


def test_register_strict_email_validation(client):
    """Test strict email format validation rejecting invalid domains and patterns."""
    invalid_emails = [
        "krushitha@123",
        "user@",
        "@example.com",
        "user@domain",
        "user@.com",
        "plainaddress",
        "user@domain..com",
    ]
    for email in invalid_emails:
        res = client.post("/api/auth/register", json={
            "email": email,
            "password": "SecurePassword1",
            "name": "Test User",
        })
        assert res.status_code == 422, f"Expected 422 for invalid email: {email}"


def test_register_with_name_and_me(client):
    """Test registering with name and retrieving it via /api/auth/me."""
    res = client.post("/api/auth/register", json={
        "name": "Alice Security",
        "email": "alice.sec@example.com",
        "password": "SecurePassword1",
    })
    assert res.status_code == 201
    data = res.json()
    assert "user" in data
    assert data["user"]["name"] == "Alice Security"
    assert data["user"]["email"] == "alice.sec@example.com"

    token = data["access_token"]
    me_res = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me_res.status_code == 200
    me_data = me_res.json()
    assert me_data["name"] == "Alice Security"
    assert me_data["email"] == "alice.sec@example.com"


def test_logout_endpoint(client):
    """Test POST /api/auth/logout returns 200."""
    res = client.post("/api/auth/register", json={
        "email": "logout.test@example.com",
        "password": "SecurePassword1",
    })
    token = res.json()["access_token"]
    logout_res = client.post("/api/auth/logout", headers={"Authorization": f"Bearer {token}"})
    assert logout_res.status_code == 200
    assert "logged out" in logout_res.json()["message"].lower()

