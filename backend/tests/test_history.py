"""
VulnScan Lite — Scan History API Unit & Integration Tests

Tests scan history retrieval, user isolation, ordering (newest first), and empty state.
"""
from datetime import datetime, timezone, timedelta
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.main import app
from app.database.database import Base, get_db
from app.database.models import User, Scan, ScanStatus
from app.core.security import hash_password, create_access_token


@pytest.fixture
def history_test_env():
    """Create an isolated test environment with SQLite and test users."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    TestingSession = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    def override_get_db():
        db = TestingSession()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)

    db = TestingSession()
    user1 = User(email="user1@example.com", password_hash=hash_password("Password123"))
    user2 = User(email="user2@example.com", password_hash=hash_password("Password123"))
    db.add_all([user1, user2])
    db.commit()
    db.refresh(user1)
    db.refresh(user2)

    token1 = create_access_token(str(user1.id))
    token2 = create_access_token(str(user2.id))

    yield client, db, user1, token1, user2, token2

    app.dependency_overrides.clear()
    Base.metadata.drop_all(bind=engine)


def test_history_unauthenticated(history_test_env):
    """GET /api/history without token must return 401."""
    client, _, _, _, _, _ = history_test_env
    res = client.get("/api/history")
    assert res.status_code == 401


def test_history_empty_state(history_test_env):
    """GET /api/history for user with no scans must return empty list."""
    client, _, _, token1, _, _ = history_test_env
    res = client.get("/api/history", headers={"Authorization": f"Bearer {token1}"})
    assert res.status_code == 200
    assert res.json() == []


def test_history_isolation_and_ordering(history_test_env):
    """GET /api/history must return only the current user's scans in reverse chronological order."""
    client, db, user1, token1, user2, token2 = history_test_env

    now = datetime.now(timezone.utc)

    # User 1 scans
    scan1_u1 = Scan(
        user_id=user1.id,
        target_url="https://site1.example.com",
        status=ScanStatus.COMPLETED,
        score=75.0,
        grade="B",
        created_at=now - timedelta(hours=2),
    )
    scan2_u1 = Scan(
        user_id=user1.id,
        target_url="https://site2.example.com",
        status=ScanStatus.COMPLETED,
        score=92.0,
        grade="A",
        created_at=now - timedelta(minutes=10),
    )

    # User 2 scan (should NEVER appear for User 1)
    scan_u2 = Scan(
        user_id=user2.id,
        target_url="https://secret.example.com",
        status=ScanStatus.COMPLETED,
        score=100.0,
        grade="A",
        created_at=now,
    )

    db.add_all([scan1_u1, scan2_u1, scan_u2])
    db.commit()

    # Query User 1 history
    res1 = client.get("/api/history", headers={"Authorization": f"Bearer {token1}"})
    assert res1.status_code == 200
    data1 = res1.json()
    assert len(data1) == 2
    # Verify newest first
    assert data1[0]["target_url"] == "https://site2.example.com"
    assert data1[0]["score"] == 92.0
    assert data1[1]["target_url"] == "https://site1.example.com"
    assert data1[1]["score"] == 75.0
    # Verify user 2 scan is absent
    assert not any(s["target_url"] == "https://secret.example.com" for s in data1)

    # Verify findings count and stage presence
    assert "findings_count" in data1[0]
    assert "stage" in data1[0]

    # Query User 2 history
    res2 = client.get("/api/history", headers={"Authorization": f"Bearer {token2}"})
    assert res2.status_code == 200
    data2 = res2.json()
    assert len(data2) == 1
    assert data2[0]["target_url"] == "https://secret.example.com"


def test_cross_user_scan_result_forbidden(history_test_env):
    """User 1 must NEVER be able to access User 2's scan result or status by scan_id."""
    client, db, user1, token1, user2, token2 = history_test_env

    # Create scan for User 2
    scan_u2 = Scan(
        user_id=user2.id,
        target_url="https://confidential.example.com",
        status=ScanStatus.COMPLETED,
        score=95.0,
        grade="A",
    )
    db.add(scan_u2)
    db.commit()
    db.refresh(scan_u2)

    # User 1 attempts to access User 2's scan result
    res = client.get(f"/api/scan/{scan_u2.id}/result", headers={"Authorization": f"Bearer {token1}"})
    assert res.status_code == 403
    assert "permission" in res.json()["detail"].lower()

    # User 1 attempts to access User 2's scan status
    status_res = client.get(f"/api/scan/{scan_u2.id}/status", headers={"Authorization": f"Bearer {token1}"})
    assert status_res.status_code == 403
    assert "permission" in status_res.json()["detail"].lower()

