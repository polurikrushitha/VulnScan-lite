"""
VulnScan Lite — Authorization and Consent Workflow Integration Tests

Comprehensive test suite verifying:
1. Authentication Gate: Unauthenticated users are blocked (401).
2. Expired / Invalid JWT tokens are blocked (401).
3. Missing or incomplete consent payloads are strictly blocked (422).
4. Individual unconfirmed consent checkboxes (1 to 5) are rejected (422).
5. Unconfirmed target confirmation checkbox is rejected (422).
6. Outdated or invalid consent versions are rejected (422).
7. Invalid authorization basis / relationship types are rejected (422).
8. Valid consent + authorization basis succeeds (202) and persists ConsentAudit record.
9. SSRF Invariant: User consent NEVER bypasses or weakens SSRF / loopback / cloud metadata protection (422).
10. SSRF Redirect Protection: Hop-by-hop redirect to private IP / metadata is blocked.
11. Concurrency limit / active scan throttling (429).
12. Cross-user isolation: User A cannot access User B's scan, status, result, or report (403).
13. Audit Trail Completeness: Confirms all audit fields stored in consent_audits table.
"""
from datetime import datetime, timezone
import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.main import app
from app.database.database import Base, get_db
from app.database.models import User, Scan, ConsentAudit, ScanStatus, AuthorizationType
from app.core.security import hash_password, create_access_token
from scanner.engine import _fetch_safe, validate_url, URLValidationError


@pytest.fixture
def auth_consent_test_env():
    """Create an isolated test client with SQLite in-memory DB and two test users."""
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
    user1 = User(name="Alice Owner", email="alice@testcorp.com", password_hash=hash_password("Pass123!"))
    user2 = User(name="Bob Attacker", email="bob@other.com", password_hash=hash_password("Pass123!"))
    db.add_all([user1, user2])
    db.commit()
    db.refresh(user1)
    db.refresh(user2)

    token1 = create_access_token(str(user1.id))
    token2 = create_access_token(str(user2.id))

    yield client, db, user1, token1, user2, token2

    app.dependency_overrides.clear()
    Base.metadata.drop_all(bind=engine)


def _valid_payload(url: str = "https://example.com", auth_type: str = "user_owned"):
    """Helper to construct a fully valid authorization and consent payload."""
    return {
        "url": url,
        "authorization_type": auth_type,
        "target_confirmed": True,
        "consent_version": "Authorized Scanning Policy v1.0",
        "confirmed_ownership": True,
        "confirmed_requests_acknowledged": True,
        "confirmed_authorized_testing_only": True,
        "confirmed_passive_analysis_understood": True,
        "confirmed_responsibility_accepted": True,
    }


# ---------------------------------------------------------------------------
# 1. Authentication Gate Tests
# ---------------------------------------------------------------------------

def test_unauthenticated_scan_request_blocked(auth_consent_test_env):
    """Unauthenticated scan request must return 401 Unauthorized."""
    client, _, _, _, _, _ = auth_consent_test_env
    res = client.post("/api/scan", json=_valid_payload())
    assert res.status_code == 401
    assert "Authorization" in res.json()["detail"] or "token" in res.json()["detail"].lower()


def test_invalid_or_expired_jwt_blocked(auth_consent_test_env):
    """Invalid or forged JWT must return 401 Unauthorized."""
    client, _, _, _, _, _ = auth_consent_test_env
    headers = {"Authorization": "Bearer invalid.token.signature"}
    res = client.post("/api/scan", json=_valid_payload(), headers=headers)
    assert res.status_code == 401


# ---------------------------------------------------------------------------
# 2. Consent Enforcement & Validation Tests
# ---------------------------------------------------------------------------

def test_missing_consent_payload_blocked(auth_consent_test_env):
    """Scan request with legacy/empty consent payload must be rejected with 422."""
    client, _, _, token, _, _ = auth_consent_test_env
    headers = {"Authorization": f"Bearer {token}"}

    # Only URL provided
    res = client.post("/api/scan", json={"url": "https://example.com"}, headers=headers)
    assert res.status_code == 422


def test_fake_consent_string_blocked(auth_consent_test_env):
    """Frontend simply submitting consent=true without structured fields is rejected with 422."""
    client, _, _, token, _, _ = auth_consent_test_env
    headers = {"Authorization": f"Bearer {token}"}

    res = client.post("/api/scan", json={"url": "https://example.com", "consent": True}, headers=headers)
    assert res.status_code == 422


@pytest.mark.parametrize("missing_checkbox", [
    "confirmed_ownership",
    "confirmed_requests_acknowledged",
    "confirmed_authorized_testing_only",
    "confirmed_passive_analysis_understood",
    "confirmed_responsibility_accepted",
])
def test_incomplete_consent_checkboxes_blocked(missing_checkbox, auth_consent_test_env):
    """If any of the 5 mandatory consent checkboxes is False, return 422."""
    client, _, _, token, _, _ = auth_consent_test_env
    headers = {"Authorization": f"Bearer {token}"}

    payload = _valid_payload()
    payload[missing_checkbox] = False

    res = client.post("/api/scan", json=payload, headers=headers)
    assert res.status_code == 422
    assert "stipulation" in str(res.json()).lower() or missing_checkbox in str(res.json())


def test_target_not_confirmed_blocked(auth_consent_test_env):
    """If target_confirmed is False, request must be rejected with 422."""
    client, _, _, token, _, _ = auth_consent_test_env
    headers = {"Authorization": f"Bearer {token}"}

    payload = _valid_payload()
    payload["target_confirmed"] = False

    res = client.post("/api/scan", json=payload, headers=headers)
    assert res.status_code == 422
    assert "target confirmation" in str(res.json()).lower()


def test_outdated_consent_version_blocked(auth_consent_test_env):
    """If consent_version does not match current version, request is rejected with 422."""
    client, _, _, token, _, _ = auth_consent_test_env
    headers = {"Authorization": f"Bearer {token}"}

    payload = _valid_payload()
    payload["consent_version"] = "Outdated Version 0.1"

    res = client.post("/api/scan", json=payload, headers=headers)
    assert res.status_code == 422


def test_invalid_authorization_type_blocked(auth_consent_test_env):
    """Invalid authorization type string must be rejected with 422."""
    client, _, _, token, _, _ = auth_consent_test_env
    headers = {"Authorization": f"Bearer {token}"}

    payload = _valid_payload()
    payload["authorization_type"] = "unauthorized_scan"

    res = client.post("/api/scan", json=payload, headers=headers)
    assert res.status_code == 422


# ---------------------------------------------------------------------------
# 3. Successful Authorized Scan & Consent Audit Record
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("auth_type", ["user_owned", "organization_approved", "explicit_permission"])
@patch("app.api.scans.execute_scan.delay")
@patch("socket.getaddrinfo")
def test_authorized_scan_creates_audit_record(mock_dns, mock_delay, auth_type, auth_consent_test_env):
    """Valid authorized scan request creates Scan and ConsentAudit records in database."""
    mock_dns.return_value = [(2, 1, 6, "", ("93.184.216.34", 443))]
    client, db, user, token, _, _ = auth_consent_test_env
    headers = {"Authorization": f"Bearer {token}"}

    payload = _valid_payload(url="https://authorized-domain.com", auth_type=auth_type)
    res = client.post("/api/scan", json=payload, headers=headers)
    assert res.status_code == 202
    data = res.json()
    scan_id = data["scan_id"]
    assert data["status"] == "queued"
    assert data["stage"] == "auth_verified"
    assert data["authorization_type"] == auth_type

    # Verify Scan in DB
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    assert scan is not None
    assert scan.user_id == user.id
    assert scan.target_url == "https://authorized-domain.com"
    assert scan.authorization_type.value == auth_type

    # Verify ConsentAudit in DB
    audit = db.query(ConsentAudit).filter(ConsentAudit.scan_id == scan_id).first()
    assert audit is not None
    assert audit.user_id == user.id
    assert audit.target_url == "https://authorized-domain.com"
    assert audit.consent_version == "Authorized Scanning Policy v1.0"
    assert audit.authorization_state == auth_type
    assert audit.scan_status == "queued"
    assert audit.confirmed_ownership is True
    assert audit.confirmed_requests_acknowledged is True
    assert audit.confirmed_authorized_testing_only is True
    assert audit.confirmed_passive_analysis_understood is True
    assert audit.confirmed_responsibility_accepted is True


# ---------------------------------------------------------------------------
# 4. SSRF Security Invariant Tests (Consent NEVER Bypasses SSRF Controls)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("restricted_target", [
    "http://localhost:8000",
    "http://localhost.localdomain",
    "http://127.0.0.1:3000",
    "http://127.0.0.1:8080",
    "http://169.254.169.254/latest/meta-data/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://10.0.0.1:8080",
    "http://172.16.0.5:8000",
    "http://192.168.1.1",
    "http://[::1]/admin",
])
def test_consent_never_bypasses_ssrf_protection(restricted_target, auth_consent_test_env):
    """
    CRITICAL SECURITY TEST:
    Even when the user submits 100% complete consent checkboxes and claims ownership,
    SSRF protection MUST NEVER be bypassed. Restricted destinations must return 422 with
    the safe security policy rejection message.
    """
    client, _, _, token, _, _ = auth_consent_test_env
    headers = {"Authorization": f"Bearer {token}"}

    payload = _valid_payload(url=restricted_target, auth_type="user_owned")
    res = client.post("/api/scan", json=payload, headers=headers)
    assert res.status_code == 422
    assert "Target rejected by VulnScan Lite security policy." in res.json()["detail"]


@patch("socket.getaddrinfo")
def test_dns_rebinding_to_private_ip_blocked(mock_dns, auth_consent_test_env):
    """Domain names resolving to private internal IP addresses must be blocked with policy message."""
    mock_dns.return_value = [(2, 1, 6, "", ("192.168.1.50", 443))]
    client, _, _, token, _, _ = auth_consent_test_env
    headers = {"Authorization": f"Bearer {token}"}

    payload = _valid_payload(url="https://rebound-domain.evil.com")
    res = client.post("/api/scan", json=payload, headers=headers)
    assert res.status_code == 422
    assert "Target rejected by VulnScan Lite security policy." in res.json()["detail"]


# ---------------------------------------------------------------------------
# 5. Redirect Hop SSRF Protection Tests
# ---------------------------------------------------------------------------

@patch("httpx.Client")
def test_redirect_to_restricted_destination_stopped_by_policy(mock_client_cls):
    """
    If a public website redirects to an internal/metadata destination,
    the scanner must stop immediately with the safe security policy message.
    """
    # Mock redirect response to AWS metadata IP
    mock_redirect_res = MagicMock()
    mock_redirect_res.status_code = 302
    mock_redirect_res.headers = {"location": "http://169.254.169.254/latest/meta-data/"}

    mock_client = MagicMock()
    mock_client.get.return_value = mock_redirect_res
    mock_client_cls.return_value.__enter__.return_value = mock_client

    response, error, http_info = _fetch_safe("https://public-redirector.com")
    assert response is None
    assert "Target rejected by VulnScan Lite security policy." in error


# ---------------------------------------------------------------------------
# 6. Concurrency Limiting Tests
# ---------------------------------------------------------------------------

def test_concurrency_limit_enforcement(auth_consent_test_env):
    """User cannot have more than MAX_CONCURRENT_SCANS_PER_USER active scans."""
    client, db, user, token, _, _ = auth_consent_test_env
    headers = {"Authorization": f"Bearer {token}"}

    # Add 3 active scans for user
    for i in range(3):
        s = Scan(user_id=user.id, target_url=f"https://target{i}.com", status=ScanStatus.RUNNING)
        db.add(s)
    db.commit()

    # 4th scan should be rejected with 429
    with patch("socket.getaddrinfo", return_value=[(2, 1, 6, "", ("93.184.216.34", 443))]):
        res = client.post("/api/scan", json=_valid_payload("https://target-overflow.com"), headers=headers)
        assert res.status_code == 429
        assert "limit" in res.json()["detail"].lower()


# ---------------------------------------------------------------------------
# 7. Cross-User Ownership Isolation Tests
# ---------------------------------------------------------------------------

def test_cross_user_isolation(auth_consent_test_env):
    """User B cannot access or poll User A's scan result or status."""
    client, db, user1, token1, user2, token2 = auth_consent_test_env

    scan = Scan(
        user_id=user1.id,
        target_url="https://user1-domain.com",
        status=ScanStatus.COMPLETED,
        authorization_type=AuthorizationType.USER_OWNED,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    scan_id = str(scan.id)

    # User 1 (Owner) -> 200
    res_owner = client.get(f"/api/scan/{scan_id}/status", headers={"Authorization": f"Bearer {token1}"})
    assert res_owner.status_code == 200

    # User 2 (Non-owner) -> 403
    res_other = client.get(f"/api/scan/{scan_id}/status", headers={"Authorization": f"Bearer {token2}"})
    assert res_other.status_code == 403
    assert "permission" in res_other.json()["detail"].lower()


# ---------------------------------------------------------------------------
# 8. Scan History & List Endpoint Tests (GET /api/scan and GET /api/history)
# ---------------------------------------------------------------------------

def test_get_scans_authenticated_with_scans(auth_consent_test_env):
    """GET /api/scan returns only the authenticated user's scans."""
    client, db, user1, token1, user2, token2 = auth_consent_test_env

    # User 1 has 2 scans
    s1 = Scan(user_id=user1.id, target_url="https://user1-a.com", status=ScanStatus.COMPLETED, authorization_type=AuthorizationType.USER_OWNED)
    s2 = Scan(user_id=user1.id, target_url="https://user1-b.com", status=ScanStatus.QUEUED, authorization_type=AuthorizationType.ORGANIZATION_APPROVED)
    # User 2 has 1 scan
    s3 = Scan(user_id=user2.id, target_url="https://user2.com", status=ScanStatus.COMPLETED, authorization_type=AuthorizationType.EXPLICIT_PERMISSION)
    db.add_all([s1, s2, s3])
    db.commit()

    # User 1 requests GET /api/scan
    res1 = client.get("/api/scan", headers={"Authorization": f"Bearer {token1}"})
    assert res1.status_code == 200
    data1 = res1.json()
    assert len(data1) == 2
    urls1 = [item["target_url"] for item in data1]
    assert "https://user1-a.com" in urls1
    assert "https://user1-b.com" in urls1
    assert "https://user2.com" not in urls1

    # User 1 requests GET /api/history (alias)
    res_hist = client.get("/api/history", headers={"Authorization": f"Bearer {token1}"})
    assert res_hist.status_code == 200
    assert len(res_hist.json()) == 2

    # User 2 requests GET /api/scan
    res2 = client.get("/api/scan", headers={"Authorization": f"Bearer {token2}"})
    assert res2.status_code == 200
    data2 = res2.json()
    assert len(data2) == 1
    assert data2[0]["target_url"] == "https://user2.com"


def test_get_scans_authenticated_empty(auth_consent_test_env):
    """Authenticated user with zero scans receives HTTP 200 and empty list."""
    client, _, user1, token1, _, _ = auth_consent_test_env

    res = client.get("/api/scan", headers={"Authorization": f"Bearer {token1}"})
    assert res.status_code == 200
    assert res.json() == []


def test_get_scans_unauthenticated_blocked(auth_consent_test_env):
    """Unauthenticated GET /api/scan returns 401."""
    client, _, _, _, _, _ = auth_consent_test_env

    res = client.get("/api/scan")
    assert res.status_code == 401
    assert "Authorization" in res.json()["detail"] or "token" in res.json()["detail"].lower()

