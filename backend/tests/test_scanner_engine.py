"""
VulnScan Lite — Scanner Engine End-to-End Unit Tests

Tests engine orchestration, redirect SSRF protection, size caps, structured error
handling, and JSON serialization using controlled mocks.
"""
from unittest.mock import patch, MagicMock
import httpx
import pytest

from scanner.engine import run_scan, validate_url, URLValidationError, _fetch_safe
from scanner.models import ScanEngineResult, SSLResult


def test_url_validation_public_domain():
    """Test validating public domains."""
    with patch("socket.getaddrinfo") as mock_dns:
        mock_dns.return_value = [(2, 1, 6, "", ("93.184.216.34", 80))]
        url = validate_url("https://example.com/test")
        assert url == "https://example.com/test"


def test_url_validation_blocks_localhost_and_private():
    """Test that localhost, 127.0.0.1, 10.0.0.1, and cloud metadata are rejected."""
    with pytest.raises(URLValidationError, match="SSRF"):
        validate_url("http://localhost:8000")

    with pytest.raises(URLValidationError, match="SSRF"):
        validate_url("http://127.0.0.1:8080/admin")

    with pytest.raises(URLValidationError, match="SSRF"):
        validate_url("http://10.0.0.1/internal")

    with pytest.raises(URLValidationError, match="SSRF"):
        validate_url("http://169.254.169.254/latest/meta-data")


def test_url_validation_blocks_dns_rebinding_to_private():
    """Test that a domain name resolving to a private IP is blocked."""
    with patch("socket.getaddrinfo") as mock_dns:
        mock_dns.return_value = [(2, 1, 6, "", ("192.168.1.50", 80))]
        with pytest.raises(URLValidationError, match="private/internal"):
            validate_url("https://evil-rebind.example.com")


@patch("scanner.engine.check_ssl")
@patch("scanner.engine._fetch_safe")
@patch("socket.getaddrinfo")
def test_run_scan_successful_pipeline(mock_dns, mock_fetch, mock_ssl):
    """Test complete successful scan orchestration returning score, grade, and findings."""
    mock_dns.return_value = [(2, 1, 6, "", ("93.184.216.34", 443))]
    
    mock_ssl.return_value = SSLResult(
        is_https=True,
        connection_successful=True,
        certificate_valid=True,
        certificate_expired=False,
        status="valid",
        points=20,
        tls_version="TLSv1.3",
        cipher="TLS_AES_256_GCM_SHA384",
        days_until_expiry=120,
        description="SSL certificate is valid.",
    )

    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.url = "https://example.com"
    mock_resp.headers = {
        "content-type": "text/html; charset=utf-8",
        "content-security-policy": "default-src 'self'",
        "x-frame-options": "SAMEORIGIN",
        "strict-transport-security": "max-age=31536000; includeSubDomains",
        "x-content-type-options": "nosniff",
        "server": "nginx/1.24.0",
    }
    mock_resp.content = b"<html><head><title>Test Target</title><meta name='generator' content='WordPress 6.4'></head><body><h1>Secure</h1></body></html>"

    from scanner.models import HTTPInfo
    http_info = HTTPInfo(
        status_code=200,
        final_url="https://example.com",
        redirect_count=0,
        response_time_ms=120.5,
        content_type="text/html; charset=utf-8",
    )
    mock_fetch.return_value = (mock_resp, None, http_info)

    result = run_scan("https://example.com")

    assert isinstance(result, ScanEngineResult)
    assert result.scan_successful is True
    assert result.score >= 90.0
    assert result.grade == "A"
    assert result.target_url == "https://example.com"
    assert result.ssl.status == "valid"
    assert result.cms.detected is True
    assert result.cms.cms_name == "WordPress"
    assert result.cms.version == "6.4"
    assert result.cms.outdated_status == "Version detected; outdated status not determined."
    assert result.html.title == "Test Target"
    assert result.server.server == "nginx/1.24.0"
    assert len(result.security_checks) > 0
    assert result.duration_seconds is not None

    # Test dictionary serialization
    result_dict = result.to_dict()
    assert isinstance(result_dict, dict)
    assert result_dict["score"] == result.score
    assert result_dict["grade"] == "A"


@patch("scanner.engine.validate_url")
def test_run_scan_ssrf_failure(mock_val):
    """Test that a validation/SSRF failure returns structured failure without crashing."""
    mock_val.side_effect = URLValidationError("Scanning internal hostname 'localhost' is prohibited (SSRF protection).")

    result = run_scan("http://localhost:8000")
    assert result.scan_successful is False
    assert result.error_type == "validation_error"
    assert "security policy" in result.error.lower()
    assert result.score == 0.0
    assert result.grade == "F"


@patch("scanner.engine.check_ssl")
@patch("scanner.engine._fetch_safe")
@patch("socket.getaddrinfo")
def test_run_scan_fetch_timeout_failure(mock_dns, mock_fetch, mock_ssl):
    """Test that a fetch timeout produces a structured failure result."""
    mock_dns.return_value = [(2, 1, 6, "", ("93.184.216.34", 443))]
    mock_ssl.return_value = SSLResult(
        is_https=True,
        connection_successful=False,
        certificate_valid=False,
        certificate_expired=False,
        status="connection_failed",
        error="Connection timed out.",
        points=-5,
        description="TLS connection timed out.",
    )
    mock_fetch.return_value = (None, "Connection timed out during HTTP request.", None)

    result = run_scan("https://timeout.example.com")
    assert result.scan_successful is False
    assert result.error_type == "fetch_error"
    assert "timed out" in result.error.lower()
    assert result.score == 0.0
    assert result.grade == "F"
