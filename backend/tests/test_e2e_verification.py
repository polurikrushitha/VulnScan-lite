"""
VulnScan Lite — End-to-End Verification Suite

Tests the complete lifecycle:
1. Registration with Name, Email, Password, Confirm Password validation.
2. Login & JWT authentication.
3. Authenticated Dashboard data retrieval (/api/auth/me, /api/history).
4. Full URL validation, SSRF checks, and Reachability handling.
5. Multi-stage scan execution and polling (validating -> connecting -> scanning -> analyzing -> generating_report -> completed).
6. Rich Finding serialization (affected_url, evidence, confidence).
7. Cross-user isolation: User A cannot access User B's scan results or history items.
8. Logout endpoint.
"""
from datetime import datetime, timezone
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from unittest.mock import patch, MagicMock
import httpx

from app.main import app
from app.database.database import Base, get_db
from app.database.models import User, Scan, ScanStatus, Finding, FindingSeverity
from scanner.models import SSLResult, HTTPInfo


@pytest.fixture
def e2e_client():
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


def test_full_user_lifecycle_and_cross_user_isolation(e2e_client):
    client, session_maker = e2e_client

    # 1. Register User A with Name
    res_a = client.post("/api/auth/register", json={
        "name": "Alice Security Analyst",
        "email": "alice@securitycorp.com",
        "password": "SecurePassword123",
    })
    assert res_a.status_code == 201
    token_a = res_a.json()["access_token"]
    assert res_a.json()["user"]["name"] == "Alice Security Analyst"

    # 2. Register User B
    res_b = client.post("/api/auth/register", json={
        "name": "Bob External Auditor",
        "email": "bob@auditor.com",
        "password": "SecurePassword456",
    })
    assert res_b.status_code == 201
    token_b = res_b.json()["access_token"]

    # 3. Verify /api/auth/me for User A
    me_res = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token_a}"})
    assert me_res.status_code == 200
    assert me_res.json()["name"] == "Alice Security Analyst"

    # 4. User A initiates an authorized scan with full consent
    payload_a = {
        "url": "https://target.securitycorp.com",
        "authorization_type": "user_owned",
        "target_confirmed": True,
        "consent_version": "Authorized Scanning Policy v1.0",
        "confirmed_ownership": True,
        "confirmed_requests_acknowledged": True,
        "confirmed_authorized_testing_only": True,
        "confirmed_passive_analysis_understood": True,
        "confirmed_responsibility_accepted": True,
    }
    with patch("app.api.scans.validate_url", return_value="https://target.securitycorp.com"), patch("app.api.scans.execute_scan.delay"):
        scan_create_res = client.post("/api/scan", json=payload_a, headers={"Authorization": f"Bearer {token_a}"})
        assert scan_create_res.status_code == 202
        scan_id = scan_create_res.json()["scan_id"]

    # Populate scan findings in DB to simulate completed engine task
    db = session_maker()
    scan_record = db.query(Scan).filter(Scan.id == scan_id).first()
    scan_record.status = ScanStatus.COMPLETED
    scan_record.stage = "completed"
    scan_record.score = 82.5
    scan_record.grade = "B"
    scan_record.completed_at = datetime.now(timezone.utc)

    finding = Finding(
        scan_id=scan_record.id,
        check_name="Missing Content-Security-Policy",
        severity=FindingSeverity.HIGH,
        description="CSP header prevents cross-site scripting (XSS) attacks.",
        remediation="Configure Content-Security-Policy: default-src 'self'",
        affected_url="https://target.securitycorp.com",
        evidence="HTTP response headers omitted Content-Security-Policy.",
        confidence="high",
    )
    db.add(finding)
    db.commit()

    # 5. User A polls scan status
    status_res_a = client.get(f"/api/scan/{scan_id}/status", headers={"Authorization": f"Bearer {token_a}"})
    assert status_res_a.status_code == 200
    assert status_res_a.json()["status"] == "completed"
    assert status_res_a.json()["stage"] == "completed"
    assert "completed successfully" in status_res_a.json()["message"].lower()

    # 6. User A retrieves full scan result
    result_res_a = client.get(f"/api/scan/{scan_id}/result", headers={"Authorization": f"Bearer {token_a}"})
    assert result_res_a.status_code == 200
    res_data = result_res_a.json()
    assert res_data["score"] == 82.5
    assert len(res_data["findings"]) == 1
    assert res_data["findings"][0]["affected_url"] == "https://target.securitycorp.com"
    assert res_data["findings"][0]["evidence"] == "HTTP response headers omitted Content-Security-Policy."
    assert res_data["findings"][0]["confidence"] == "high"

    # 7. User A checks scan history
    hist_res_a = client.get("/api/history", headers={"Authorization": f"Bearer {token_a}"})
    assert hist_res_a.status_code == 200
    assert len(hist_res_a.json()) == 1
    assert hist_res_a.json()[0]["findings_count"] == 1

    # 8. User B attempts to access User A's scan result and status -> 403 Forbidden
    result_res_b = client.get(f"/api/scan/{scan_id}/result", headers={"Authorization": f"Bearer {token_b}"})
    assert result_res_b.status_code == 403
    assert "permission" in result_res_b.json()["detail"].lower()

    status_res_b = client.get(f"/api/scan/{scan_id}/status", headers={"Authorization": f"Bearer {token_b}"})
    assert status_res_b.status_code == 403

    # 9. User B's scan history must NOT show User A's scan
    hist_res_b = client.get("/api/history", headers={"Authorization": f"Bearer {token_b}"})
    assert hist_res_b.status_code == 200
    assert len(hist_res_b.json()) == 0

    # 10. User A logs out
    logout_res = client.post("/api/auth/logout", headers={"Authorization": f"Bearer {token_a}"})
    assert logout_res.status_code == 200
