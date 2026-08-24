"""
VulnScan Lite — PDF Reports API Unit & Integration Tests

Tests PDF report generation via ReportLab, ownership access enforcement,
content-type verification, and incomplete scan handling.
"""
from datetime import datetime, timezone
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
def report_test_env():
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
    owner = User(email="report_owner@example.com", password_hash=hash_password("Password123"))
    other = User(email="report_other@example.com", password_hash=hash_password("Password123"))
    db.add_all([owner, other])
    db.commit()
    db.refresh(owner)
    db.refresh(other)

    owner_token = create_access_token(str(owner.id))
    other_token = create_access_token(str(other.id))

    yield client, db, owner, owner_token, other, other_token

    app.dependency_overrides.clear()
    Base.metadata.drop_all(bind=engine)


def test_download_pdf_unauthenticated(report_test_env):
    """GET /api/reports/{id}/pdf without token must return 401."""
    client, _, _, _, _, _ = report_test_env
    res = client.get("/api/reports/some-scan-id/pdf")
    assert res.status_code == 401


def test_download_pdf_not_found(report_test_env):
    """GET /api/reports/{id}/pdf with non-existent scan ID must return 404."""
    client, _, _, owner_token, _, _ = report_test_env
    res = client.get(
        "/api/reports/00000000-0000-0000-0000-000000000000/pdf",
        headers={"Authorization": f"Bearer {owner_token}"},
    )
    assert res.status_code == 404
    assert "not found" in res.json()["detail"].lower()


def test_download_pdf_incomplete_scan(report_test_env):
    """GET /api/reports/{id}/pdf on a running/queued scan must return 400."""
    client, db, owner, owner_token, _, _ = report_test_env

    scan = Scan(user_id=owner.id, target_url="https://example.com", status=ScanStatus.RUNNING)
    db.add(scan)
    db.commit()
    db.refresh(scan)

    res = client.get(
        f"/api/reports/{scan.id}/pdf",
        headers={"Authorization": f"Bearer {owner_token}"},
    )
    assert res.status_code == 400
    assert "not yet complete" in res.json()["detail"].lower()


def test_download_pdf_ownership_enforcement(report_test_env):
    """GET /api/reports/{id}/pdf by a non-owner user must return 403 Forbidden."""
    client, db, owner, _, other, other_token = report_test_env

    scan = Scan(
        user_id=owner.id,
        target_url="https://example.com",
        status=ScanStatus.COMPLETED,
        score=95.0,
        grade="A",
        completed_at=datetime.now(timezone.utc),
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    res = client.get(
        f"/api/reports/{scan.id}/pdf",
        headers={"Authorization": f"Bearer {other_token}"},
    )
    assert res.status_code == 403
    assert "access denied" in res.json()["detail"].lower()


def test_download_pdf_success_content(report_test_env):
    """GET /api/reports/{id}/pdf on a completed scan must return valid PDF bytes."""
    client, db, owner, owner_token, _, _ = report_test_env

    scan = Scan(
        user_id=owner.id,
        target_url="https://example.com",
        status=ScanStatus.COMPLETED,
        score=85.0,
        grade="B+",
        started_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc),
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    # Add diagnostic results
    result = ScanResult(
        scan_id=scan.id,
        ssl_data={
            "is_https": True,
            "certificate_valid": True,
            "tls_version": "TLSv1.3",
            "cipher": "TLS_AES_256_GCM_SHA384",
            "subject": "CN=example.com",
            "issuer": "CN=DigiCert",
            "not_after": "2027-01-01",
            "days_until_expiry": 200,
        },
        cms_data={
            "detected": True,
            "cms_name": "WordPress",
            "version": "6.4",
            "confidence": "high",
            "detection_source": "meta[generator]",
        },
        html_data={
            "title": "Example Domain",
            "generator": "WordPress 6.4",
            "technology_indicators": ["jQuery", "Bootstrap"],
        },
    )
    check = SecurityCheck(
        scan_id=scan.id,
        check_name="Content-Security-Policy",
        category="Headers",
        status=CheckStatus.PASSED,
        points=10,
        description="CSP header is set.",
    )
    finding = Finding(
        scan_id=scan.id,
        check_name="Missing X-Frame-Options",
        severity=FindingSeverity.MEDIUM,
        description="X-Frame-Options is missing.",
        remediation="Add X-Frame-Options: SAMEORIGIN",
    )
    db.add_all([result, check, finding])
    db.commit()

    res = client.get(
        f"/api/reports/{scan.id}/pdf",
        headers={"Authorization": f"Bearer {owner_token}"},
    )

    assert res.status_code == 200
    assert res.headers["content-type"] == "application/pdf"
    assert "vulnscan-" in res.headers["content-disposition"]
    # PDF magic byte signature check
    assert res.content.startswith(b"%PDF-")
    assert len(res.content) > 1000
