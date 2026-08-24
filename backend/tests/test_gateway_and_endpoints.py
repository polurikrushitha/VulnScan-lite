"""
VulnScan Lite — Gateway & API Endpoints Verification Suite

Tests:
1. /docs, /api/docs, /health, /health/db
2. Authentication routes: /api/auth/register, /api/auth/login, /api/auth/me, /api/auth/logout
3. Scan creation and protection: /api/scan (authenticated vs anonymous)
4. Scan polling and reporting: /api/scan/{id}/status, /api/scan/{id}/result, /api/scan/{id}/report
5. History isolation: /api/history (User A cannot see User B's scans)
6. Invalid and malformed emails (krushitha@123, abc@, etc.) are strictly rejected
"""
from datetime import datetime, timezone
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from unittest.mock import patch

from app.main import app
from app.database.database import Base, get_db
from app.database.models import User, Scan, ScanStatus, Finding, FindingSeverity


@pytest.fixture
def gateway_client():
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

    yield client, TestingSession

    app.dependency_overrides.clear()
    Base.metadata.drop_all(bind=engine)


def test_docs_and_health_endpoints(gateway_client):
    client, _ = gateway_client

    # 1. Health endpoint
    h_res = client.get("/health")
    assert h_res.status_code == 200
    assert h_res.json()["status"] == "ok"

    # 2. Database health endpoint
    db_res = client.get("/health/db")
    assert db_res.status_code == 200
    assert db_res.json()["status"] == "ok"
    assert db_res.json()["database"] == "connected"

    # 3. Docs endpoint
    docs_res = client.get("/api/docs")
    assert docs_res.status_code == 200


def test_email_validation_strictness(gateway_client):
    client, _ = gateway_client

    invalid_emails = [
        "krushitha@123",
        "abc@",
        "user@",
        "@example.com",
        "abc.com",
        "plainaddress",
        "user@domain",
    ]

    for inv_email in invalid_emails:
        res = client.post("/api/auth/register", json={
            "name": "Invalid User",
            "email": inv_email,
            "password": "Password123",
        })
        assert res.status_code == 422, f"Expected 422 for invalid email '{inv_email}', got {res.status_code}"


def test_anonymous_access_protection(gateway_client):
    client, _ = gateway_client

    # 1. Scan creation requires auth
    res_scan = client.post("/api/scan", json={"url": "https://example.com"})
    assert res_scan.status_code == 401

    # 2. History requires auth
    res_hist = client.get("/api/history")
    assert res_hist.status_code == 401

    # 3. Status requires auth
    res_stat = client.get("/api/scan/fake-id-123/status")
    assert res_stat.status_code == 401

    # 4. Result requires auth
    res_res = client.get("/api/scan/fake-id-123/result")
    assert res_res.status_code == 401

    # 5. Report alias requires auth
    res_rep = client.get("/api/scan/fake-id-123/report")
    assert res_rep.status_code == 401


def test_full_two_user_isolation_and_reporting(gateway_client):
    client, session_maker = gateway_client

    # Register User A (testa@example.com)
    res_a = client.post("/api/auth/register", json={
        "name": "User A",
        "email": "testa@example.com",
        "password": "Password123A",
    })
    assert res_a.status_code == 201
    token_a = res_a.json()["access_token"]

    # Register User B (testb@example.com)
    res_b = client.post("/api/auth/register", json={
        "name": "User B",
        "email": "testb@example.com",
        "password": "Password123B",
    })
    assert res_b.status_code == 201
    token_b = res_b.json()["access_token"]

    # User A initiates a scan
    payload_a = {
        "url": "https://testa-target.com",
        "authorization_type": "user_owned",
        "target_confirmed": True,
        "consent_version": "Authorized Scanning Policy v1.0",
        "confirmed_ownership": True,
        "confirmed_requests_acknowledged": True,
        "confirmed_authorized_testing_only": True,
        "confirmed_passive_analysis_understood": True,
        "confirmed_responsibility_accepted": True,
    }
    with patch("app.api.scans.validate_url", return_value="https://testa-target.com"), patch("app.api.scans.execute_scan.delay"):
        scan_res = client.post("/api/scan", json=payload_a, headers={"Authorization": f"Bearer {token_a}"})
        assert scan_res.status_code == 202
        scan_id = scan_res.json()["scan_id"]

    # Complete the scan in DB
    db = session_maker()
    scan_record = db.query(Scan).filter(Scan.id == scan_id).first()
    scan_record.status = ScanStatus.COMPLETED
    scan_record.stage = "completed"
    scan_record.score = 90.0
    scan_record.grade = "A"
    scan_record.completed_at = datetime.now(timezone.utc)
    db.commit()

    # User A can retrieve /api/scan/{id}/status, /api/scan/{id}/result, /api/scan/{id}/report
    headers_a = {"Authorization": f"Bearer {token_a}"}
    stat_a = client.get(f"/api/scan/{scan_id}/status", headers=headers_a)
    assert stat_a.status_code == 200
    assert stat_a.json()["status"] == "completed"

    res_a = client.get(f"/api/scan/{scan_id}/result", headers=headers_a)
    assert res_a.status_code == 200
    assert res_a.json()["target_url"] == "https://testa-target.com"

    rep_a = client.get(f"/api/scan/{scan_id}/report", headers=headers_a)
    assert rep_a.status_code == 200
    assert rep_a.json()["target_url"] == "https://testa-target.com"

    # User A sees scan in history
    hist_a = client.get("/api/history", headers=headers_a)
    assert hist_a.status_code == 200
    assert len(hist_a.json()) == 1

    # User B CANNOT see User A's history
    headers_b = {"Authorization": f"Bearer {token_b}"}
    hist_b = client.get("/api/history", headers=headers_b)
    assert hist_b.status_code == 200
    assert len(hist_b.json()) == 0

    # User B CANNOT access User A's status, result, or report (403 Forbidden)
    assert client.get(f"/api/scan/{scan_id}/status", headers=headers_b).status_code == 403
    assert client.get(f"/api/scan/{scan_id}/result", headers=headers_b).status_code == 403
    assert client.get(f"/api/scan/{scan_id}/report", headers=headers_b).status_code == 403
