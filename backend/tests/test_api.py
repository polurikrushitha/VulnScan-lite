"""
VulnScan Lite — FastAPI Scan & Health API Integration Tests

Tests health endpoints, unauthenticated barriers, scan queuing, SSRF protection,
status polling, report retrieval, and ownership authorization using TestClient.
"""
from unittest.mock import patch, MagicMock
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.main import app
from app.database.database import Base, get_db
from app.database.models import User, Scan, ScanResult, SecurityCheck, Finding, ScanStatus, CheckStatus, FindingSeverity
from app.core.security import hash_password, create_access_token


@pytest.fixture
def test_client_and_db():
    """Create an isolated test client with SQLite in-memory DB and test users."""
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
    # Create two test users for ownership verification
    user1 = User(email="owner@example.com", password_hash=hash_password("Password123"))
    user2 = User(email="other@example.com", password_hash=hash_password("Password123"))
    db.add_all([user1, user2])
    db.commit()
    db.refresh(user1)
    db.refresh(user2)

    token1 = create_access_token(str(user1.id))
    token2 = create_access_token(str(user2.id))

    yield client, db, user1, token1, user2, token2

    app.dependency_overrides.clear()
    Base.metadata.drop_all(bind=engine)


# ---------------------------------------------------------------------------
# Health checks
# ---------------------------------------------------------------------------

def test_health_check(test_client_and_db):
    """GET /health must return 200 with status ok."""
    client, _, _, _, _, _ = test_client_and_db
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_db_health_check(test_client_and_db):
    """GET /health/db must return 200 with database status."""
    client, _, _, _, _, _ = test_client_and_db
    response = client.get("/health/db")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert response.json()["database"] == "connected"


# ---------------------------------------------------------------------------
# Unauthenticated Protection
# ---------------------------------------------------------------------------

def test_unauthenticated_requests(test_client_and_db):
    """Endpoints requiring authentication must return 401 when no token is provided."""
    client, _, _, _, _, _ = test_client_and_db

    assert client.post("/api/scan", json={"url": "https://example.com"}).status_code == 401
    assert client.get("/api/scan/some-id/status").status_code == 401
    assert client.get("/api/scan/some-id/result").status_code == 401
    assert client.get("/api/history").status_code == 401


# ---------------------------------------------------------------------------
# Scan Creation & SSRF Protection
# ---------------------------------------------------------------------------

VALID_CONSENT_PAYLOAD = {
    "url": "https://example.com",
    "authorization_type": "user_owned",
    "target_confirmed": True,
    "consent_version": "Authorized Scanning Policy v1.0",
    "confirmed_ownership": True,
    "confirmed_requests_acknowledged": True,
    "confirmed_authorized_testing_only": True,
    "confirmed_passive_analysis_understood": True,
    "confirmed_responsibility_accepted": True,
}


def test_create_scan_ssrf_protection(test_client_and_db):
    """POST /api/scan must reject private IPs and localhost with 422."""
    client, _, _, token, _, _ = test_client_and_db
    headers = {"Authorization": f"Bearer {token}"}

    # Blocked hostnames
    payload1 = {**VALID_CONSENT_PAYLOAD, "url": "http://localhost:8000"}
    res = client.post("/api/scan", json=payload1, headers=headers)
    assert res.status_code == 422
    assert "security policy" in res.json()["detail"].lower()

    # Blocked IP
    payload2 = {**VALID_CONSENT_PAYLOAD, "url": "http://127.0.0.1:5000"}
    res_ip = client.post("/api/scan", json=payload2, headers=headers)
    assert res_ip.status_code == 422


@patch("app.api.scans.execute_scan.delay")
@patch("socket.getaddrinfo")
def test_create_scan_success(mock_dns, mock_delay, test_client_and_db):
    """POST /api/scan must create a queued record, trigger Celery task, and return 202."""
    mock_dns.return_value = [(2, 1, 6, "", ("93.184.216.34", 443))]
    client, db, user, token, _, _ = test_client_and_db
    headers = {"Authorization": f"Bearer {token}"}

    res = client.post("/api/scan", json=VALID_CONSENT_PAYLOAD, headers=headers)
    assert res.status_code == 202
    data = res.json()
    assert "scan_id" in data
    assert data["status"] == "queued"

    # Verify task dispatch
    mock_delay.assert_called_once_with(data["scan_id"], "https://example.com")

    # Verify record in DB
    scan = db.query(Scan).filter(Scan.id == data["scan_id"]).first()
    assert scan is not None
    assert scan.user_id == user.id
    assert scan.status == ScanStatus.QUEUED


# ---------------------------------------------------------------------------
# Status Polling & Ownership Enforcement
# ---------------------------------------------------------------------------

def test_scan_status_and_ownership(test_client_and_db):
    """Test polling scan status and verifying that only the owner can access it."""
    client, db, user1, token1, user2, token2 = test_client_and_db

    # Create scan for user1
    scan = Scan(user_id=user1.id, target_url="https://example.com", status=ScanStatus.RUNNING)
    db.add(scan)
    db.commit()
    db.refresh(scan)
    scan_id = str(scan.id)

    # 1. Owner requests status -> 200
    res_owner = client.get(f"/api/scan/{scan_id}/status", headers={"Authorization": f"Bearer {token1}"})
    assert res_owner.status_code == 200
    assert res_owner.json()["status"] == "running"

    # 2. Non-owner requests status -> 403 Forbidden
    res_other = client.get(f"/api/scan/{scan_id}/status", headers={"Authorization": f"Bearer {token2}"})
    assert res_other.status_code == 403
    assert "permission" in res_other.json()["detail"].lower()

    # 3. Non-existent scan -> 404
    res_404 = client.get("/api/scan/00000000-0000-0000-0000-000000000000/status", headers={"Authorization": f"Bearer {token1}"})
    assert res_404.status_code == 404


# ---------------------------------------------------------------------------
# Result Retrieval & Incomplete Checks
# ---------------------------------------------------------------------------

def test_scan_result_lifecycle(test_client_and_db):
    """Test retrieving scan results for completed, incomplete, and unauthorized scans."""
    client, db, user1, token1, user2, token2 = test_client_and_db

    # 1. Incomplete scan (queued)
    scan = Scan(user_id=user1.id, target_url="https://example.com", status=ScanStatus.QUEUED)
    db.add(scan)
    db.commit()
    db.refresh(scan)
    scan_id = str(scan.id)

    res_incomplete = client.get(f"/api/scan/{scan_id}/result", headers={"Authorization": f"Bearer {token1}"})
    assert res_incomplete.status_code == 400
    assert "not yet complete" in res_incomplete.json()["detail"].lower()

    # 2. Complete the scan and add results
    scan.status = ScanStatus.COMPLETED
    scan.score = 80.0
    scan.grade = "B+"
    scan_result = ScanResult(
        scan_id=scan.id,
        ssl_data={"is_https": True, "status": "valid"},
        header_data={"server": "nginx"},
    )
    check = SecurityCheck(
        scan_id=scan.id,
        check_name="Content-Security-Policy",
        category="Headers",
        status=CheckStatus.PASSED,
        points=10,
        description="CSP present",
    )
    finding = Finding(
        scan_id=scan.id,
        check_name="Missing X-Frame-Options",
        severity=FindingSeverity.MEDIUM,
        description="XFO missing",
        remediation="Add X-Frame-Options",
    )
    db.add_all([scan_result, check, finding])
    db.commit()

    # 3. Owner retrieves completed result -> 200
    res_completed = client.get(f"/api/scan/{scan_id}/result", headers={"Authorization": f"Bearer {token1}"})
    assert res_completed.status_code == 200
    data = res_completed.json()
    assert data["status"] == "completed"
    assert data["score"] == 80.0
    assert data["grade"] == "B+"
    assert len(data["security_checks"]) == 1
    assert len(data["findings"]) == 1
    assert data["findings"][0]["severity"] == "medium"

    # 4. Non-owner requests completed result -> 403 Forbidden
    res_other = client.get(f"/api/scan/{scan_id}/result", headers={"Authorization": f"Bearer {token2}"})
    assert res_other.status_code == 403
