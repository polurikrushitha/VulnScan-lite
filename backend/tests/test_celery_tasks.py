"""
VulnScan Lite — Celery Scan Tasks Unit Tests

Tests Celery task execution, database state transitions, relational persistence,
and error handling using an isolated test database.
"""
from datetime import datetime, timezone
from unittest.mock import patch, MagicMock
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database.database import Base
from app.database.models import User, Scan, ScanResult, SecurityCheck, Finding, ScanStatus, CheckStatus, FindingSeverity
from app.tasks.scan_tasks import execute_scan
from scanner.models import (
    ScanEngineResult,
    SSLResult,
    HeaderAnalysisResult,
    HeaderCheckResult,
    CMSResult,
    HTMLAnalysisResult,
    HTTPInfo,
    ServerInfo,
    SecurityCheckItem,
    FindingItem,
)


@pytest.fixture
def task_db():
    """Create an in-memory SQLite database session for task testing."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    TestingSession = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    session = TestingSession()

    yield session

    session.close()
    Base.metadata.drop_all(bind=engine)


def test_execute_scan_successful_workflow(task_db):
    """Test full successful scan task execution and PostgreSQL persistence."""
    # 1. Create User and queued Scan
    user = User(email="task_tester@example.com", password_hash="hash123")
    task_db.add(user)
    task_db.commit()
    task_db.refresh(user)

    scan = Scan(user_id=user.id, target_url="https://example.com", status=ScanStatus.QUEUED)
    task_db.add(scan)
    task_db.commit()
    task_db.refresh(scan)

    scan_id = str(scan.id)

    # 2. Mock scanner engine output
    mock_engine_result = ScanEngineResult(
        target_url="https://example.com",
        scan_successful=True,
        score=85.0,
        grade="B+",
        http=HTTPInfo(status_code=200, final_url="https://example.com", redirect_count=0),
        ssl=SSLResult(
            is_https=True,
            connection_successful=True,
            certificate_valid=True,
            certificate_expired=False,
            status="valid",
            points=20,
            tls_version="TLSv1.3",
            cipher="TLS_AES_256_GCM_SHA384",
            days_until_expiry=90,
            description="SSL certificate is valid.",
        ),
        headers=HeaderAnalysisResult(
            checks=[
                HeaderCheckResult(header_name="Content-Security-Policy", present=True, value="default-src 'self'", points=10, status="passed", description="CSP is set", remediation="", category="Headers"),
                HeaderCheckResult(header_name="X-Frame-Options", present=False, value=None, points=-10, status="failed", description="XFO missing", remediation="Add XFO header", category="Headers"),
            ],
            server="nginx/1.24",
        ),
        cms=CMSResult(detected=True, cms_name="WordPress", version="6.4", detection_source="meta[generator]", confidence="high", version_exposed=True, outdated_status="Version detected; outdated status not determined."),
        html=HTMLAnalysisResult(is_html=True, title="Example", technology_indicators=["jQuery"]),
        server=ServerInfo(server="nginx/1.24"),
        security_checks=[
            SecurityCheckItem(check_name="SSL/TLS Certificate", category="SSL/TLS", status="passed", points=20, description="SSL valid"),
            SecurityCheckItem(check_name="Content-Security-Policy", category="Headers", status="passed", points=10, description="CSP passed"),
            SecurityCheckItem(check_name="X-Frame-Options", category="Headers", status="failed", points=-10, description="XFO missing"),
        ],
        findings=[
            FindingItem(check_name="Missing X-Frame-Options", severity="medium", description="XFO missing from response", remediation="Add X-Frame-Options: SAMEORIGIN", category="Headers"),
        ],
    )

    with patch("app.tasks.scan_tasks._get_db", return_value=task_db):
        with patch("app.tasks.scan_tasks.run_scan", return_value=mock_engine_result):
            res = execute_scan(scan_id=scan_id, target_url="https://example.com")
            assert res["status"] == "completed"

    # 3. Verify database updates
    updated_scan = task_db.query(Scan).filter(Scan.id == scan_id).first()
    assert updated_scan.status == ScanStatus.COMPLETED
    assert updated_scan.score == 85.0
    assert updated_scan.grade == "B+"
    assert updated_scan.started_at is not None
    assert updated_scan.completed_at is not None
    assert updated_scan.error_message is None

    # Verify ScanResult record
    scan_result = task_db.query(ScanResult).filter(ScanResult.scan_id == scan_id).first()
    assert scan_result is not None
    assert scan_result.ssl_data["status"] == "valid"
    assert scan_result.cms_data["cms_name"] == "WordPress"
    assert scan_result.html_data["title"] == "Example"

    # Verify SecurityChecks
    checks = task_db.query(SecurityCheck).filter(SecurityCheck.scan_id == scan_id).all()
    assert len(checks) == 3
    assert any(c.check_name == "Content-Security-Policy" and c.status == CheckStatus.PASSED for c in checks)
    assert any(c.check_name == "X-Frame-Options" and c.status == CheckStatus.FAILED for c in checks)

    # Verify Findings
    findings = task_db.query(Finding).filter(Finding.scan_id == scan_id).all()
    assert len(findings) == 1
    assert findings[0].check_name == "Missing X-Frame-Options"
    assert findings[0].severity == FindingSeverity.MEDIUM


def test_execute_scan_engine_failure(task_db):
    """Test task execution when scanner engine encounters an unrecoverable target error."""
    user = User(email="task_fail@example.com", password_hash="hash123")
    task_db.add(user)
    task_db.commit()

    scan = Scan(user_id=user.id, target_url="https://unreachable.example.com", status=ScanStatus.QUEUED)
    task_db.add(scan)
    task_db.commit()

    scan_id = str(scan.id)

    mock_engine_result = ScanEngineResult(
        target_url="https://unreachable.example.com",
        scan_successful=False,
        score=0.0,
        grade="F",
        error_type="fetch_error",
        error="Connection timed out.",
    )

    with patch("app.tasks.scan_tasks._get_db", return_value=task_db):
        with patch("app.tasks.scan_tasks.run_scan", return_value=mock_engine_result):
            res = execute_scan(scan_id=scan_id, target_url="https://unreachable.example.com")
            assert res["status"] == "failed"

    updated_scan = task_db.query(Scan).filter(Scan.id == scan_id).first()
    assert updated_scan.status == ScanStatus.FAILED
    assert updated_scan.error_message == "Connection timed out."
    assert updated_scan.completed_at is not None


def test_execute_scan_record_not_found(task_db):
    """Test task execution when an invalid scan UUID is provided."""
    with patch("app.tasks.scan_tasks._get_db", return_value=task_db):
        res = execute_scan(scan_id="00000000-0000-0000-0000-000000000000", target_url="https://example.com")
        assert res["status"] == "failed"
        assert "not found" in res["error"].lower()
