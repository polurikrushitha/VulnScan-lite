"""
VulnScan Lite — Database Models & Relationship Tests

Tests:
  - User model creation and uniqueness constraint
  - Scan model creation, foreign key to User, status Enum defaults
  - ScanResult model creation, 1-to-1 relationship with Scan, JSON fields
  - SecurityCheck model creation, 1-to-many relationship with Scan
  - Finding model creation, 1-to-many relationship with Scan
  - Cascade deletion (deleting a User cascades to their Scans, Results, Checks, Findings)
  - Scan ownership isolation logic
"""
import pytest
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import IntegrityError

from app.database.database import Base
from app.database.models import (
    User,
    Scan,
    ScanResult,
    SecurityCheck,
    Finding,
    ScanStatus,
    CheckStatus,
    FindingSeverity,
)

TEST_DB_URL = "sqlite:///:memory:"
engine = create_engine(
    TEST_DB_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


@pytest.fixture
def db():
    """Create fresh database tables and yield a test session."""
    Base.metadata.create_all(bind=engine)
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=engine)


def test_create_user(db):
    """User should be created with UUID, unique email, and timestamp."""
    user = User(
        email="testuser@example.com",
        password_hash="fakehash123",
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    assert user.id is not None
    assert len(user.id) == 36  # UUID format
    assert user.email == "testuser@example.com"
    assert user.created_at is not None
    assert user.updated_at is not None


def test_user_email_unique(db):
    """Duplicate email in User table must violate uniqueness."""
    u1 = User(email="duplicate@example.com", password_hash="hash1")
    u2 = User(email="duplicate@example.com", password_hash="hash2")
    db.add(u1)
    db.commit()

    db.add(u2)
    with pytest.raises(IntegrityError):
        db.commit()
    db.rollback()


def test_scan_and_relationships(db):
    """Scan should link to User and support ScanResult, SecurityChecks, and Findings."""
    user = User(email="owner@example.com", password_hash="hash")
    db.add(user)
    db.commit()

    scan = Scan(
        user_id=user.id,
        target_url="https://example.com",
        status=ScanStatus.QUEUED,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    assert scan.id is not None
    assert scan.user_id == user.id
    assert scan.status == ScanStatus.QUEUED
    assert scan.created_at is not None

    # ScanResult (1-to-1)
    result = ScanResult(
        scan_id=scan.id,
        ssl_data={"is_https": True, "tls_version": "TLSv1.3"},
        header_data={"server": "nginx"},
        cms_data={"detected": False},
    )
    db.add(result)

    # SecurityCheck (1-to-many)
    check1 = SecurityCheck(
        scan_id=scan.id,
        check_name="Content-Security-Policy",
        category="Headers",
        status=CheckStatus.PASSED,
        points=10,
        description="CSP header is present",
    )
    check2 = SecurityCheck(
        scan_id=scan.id,
        check_name="X-Frame-Options",
        category="Headers",
        status=CheckStatus.FAILED,
        points=-10,
        description="X-Frame-Options missing",
    )
    db.add_all([check1, check2])

    # Finding (1-to-many)
    finding = Finding(
        scan_id=scan.id,
        check_name="X-Frame-Options",
        severity=FindingSeverity.HIGH,
        description="Clickjacking vulnerability due to missing X-Frame-Options",
        remediation="Add 'X-Frame-Options: DENY' or 'SAMEORIGIN' header.",
    )
    db.add(finding)
    db.commit()

    # Query scan and verify relationships
    queried_scan = db.query(Scan).filter(Scan.id == scan.id).first()
    assert queried_scan.user.email == "owner@example.com"
    assert queried_scan.result.ssl_data["is_https"] is True
    assert len(queried_scan.security_checks) == 2
    assert len(queried_scan.findings) == 1
    assert queried_scan.findings[0].severity == FindingSeverity.HIGH


def test_scan_cascade_deletion(db):
    """Deleting a User must cascade and delete all associated scans and results."""
    user = User(email="cascade@example.com", password_hash="hash")
    db.add(user)
    db.commit()

    scan = Scan(user_id=user.id, target_url="https://cascade.com", status=ScanStatus.COMPLETED)
    db.add(scan)
    db.commit()

    result = ScanResult(scan_id=scan.id, ssl_data={"is_https": True})
    check = SecurityCheck(scan_id=scan.id, check_name="Test", category="Test", status=CheckStatus.PASSED)
    finding = Finding(scan_id=scan.id, check_name="Test", severity=FindingSeverity.LOW, description="Desc")
    db.add_all([result, check, finding])
    db.commit()

    scan_id = scan.id
    # Delete User
    db.delete(user)
    db.commit()

    # Verify everything was deleted
    assert db.query(Scan).filter(Scan.id == scan_id).first() is None
    assert db.query(ScanResult).filter(ScanResult.scan_id == scan_id).first() is None
    assert db.query(SecurityCheck).filter(SecurityCheck.scan_id == scan_id).first() is None
    assert db.query(Finding).filter(Finding.scan_id == scan_id).first() is None


def test_scan_ownership_isolation(db):
    """User A should not see or access scans belonging to User B."""
    user_a = User(email="usera@example.com", password_hash="hash")
    user_b = User(email="userb@example.com", password_hash="hash")
    db.add_all([user_a, user_b])
    db.commit()

    scan_a = Scan(user_id=user_a.id, target_url="https://a.example.com", status=ScanStatus.COMPLETED)
    scan_b = Scan(user_id=user_b.id, target_url="https://b.example.com", status=ScanStatus.COMPLETED)
    db.add_all([scan_a, scan_b])
    db.commit()

    # Query scans for user A only
    user_a_scans = db.query(Scan).filter(Scan.user_id == user_a.id).all()
    assert len(user_a_scans) == 1
    assert user_a_scans[0].target_url == "https://a.example.com"

    # Query scans for user B only
    user_b_scans = db.query(Scan).filter(Scan.user_id == user_b.id).all()
    assert len(user_b_scans) == 1
    assert user_b_scans[0].target_url == "https://b.example.com"
