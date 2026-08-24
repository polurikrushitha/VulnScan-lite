"""
VulnScan Lite — Tests for Security Header Analysis
"""
import pytest
from scanner.headers import analyze_headers


def test_all_required_headers_present():
    """All required headers present should give positive points."""
    headers = {
        "Content-Security-Policy": "default-src 'self'",
        "X-Frame-Options": "SAMEORIGIN",
        "Strict-Transport-Security": "max-age=31536000",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "camera=()",
    }
    result = analyze_headers(headers)
    for check in result.checks:
        if check.header_name in ("Content-Security-Policy", "X-Frame-Options", "Strict-Transport-Security"):
            assert check.points == 10, f"{check.header_name} should be +10"
            assert check.present is True


def test_all_required_headers_missing():
    """All required headers missing should give negative points."""
    result = analyze_headers({})
    for check in result.checks:
        if check.header_name in ("Content-Security-Policy", "X-Frame-Options", "Strict-Transport-Security"):
            assert check.points == -10, f"{check.header_name} should be -10"
            assert check.present is False


def test_bonus_headers_not_penalised():
    """Missing bonus headers should have 0 points, not negative."""
    result = analyze_headers({})
    bonus_names = {"X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy"}
    for check in result.checks:
        if check.header_name in bonus_names:
            assert check.points == 0, f"{check.header_name} should be 0 when missing"


def test_header_value_captured():
    """Header values should be captured in the result."""
    headers = {"Content-Security-Policy": "default-src 'self' https:"}
    result = analyze_headers(headers)
    csp = next(c for c in result.checks if c.header_name == "Content-Security-Policy")
    assert csp.value == "default-src 'self' https:"


def test_server_header_captured():
    """Server and X-Powered-By headers should be extracted."""
    headers = {
        "Server": "nginx/1.24.0",
        "X-Powered-By": "PHP/8.1",
    }
    result = analyze_headers(headers)
    assert result.server == "nginx/1.24.0"
    assert result.x_powered_by == "PHP/8.1"


def test_case_insensitive_headers():
    """Header detection should be case-insensitive."""
    headers = {
        "content-security-policy": "default-src 'self'",
        "x-frame-options": "DENY",
        "strict-transport-security": "max-age=86400",
    }
    result = analyze_headers(headers)
    csp = next(c for c in result.checks if c.header_name == "Content-Security-Policy")
    assert csp.present is True
