"""
VulnScan Lite — Remediation Engine Unit Tests

Tests remediation lookups, Nginx and Apache guidance snippets, and fallback responses.
"""
import pytest
from app.services.remediation import get_remediation, get_remediation_text, REMEDIATION_DATABASE


def test_remediation_lookup_csp():
    """Test retrieving remediation guidance for Content-Security-Policy."""
    entry = get_remediation("Content-Security-Policy")
    assert entry is not None
    assert "Content-Security-Policy" in entry["issue"]
    assert "XSS" in entry["why_it_matters"]
    assert "add_header Content-Security-Policy" in entry["example"]
    assert entry["severity"] == "high"


def test_remediation_lookup_xfo():
    """Test retrieving remediation guidance for X-Frame-Options."""
    entry = get_remediation("X-Frame-Options")
    assert entry is not None
    assert "clickjacking" in entry["why_it_matters"].lower()
    assert "SAMEORIGIN" in entry["example"]
    assert entry["severity"] == "medium"


def test_remediation_lookup_hsts():
    """Test retrieving remediation guidance for Strict-Transport-Security."""
    entry = get_remediation("Strict-Transport-Security")
    assert entry is not None
    assert "HTTPS" in entry["why_it_matters"]
    assert "max-age=31536000" in entry["example"]
    assert entry["severity"] == "high"


def test_remediation_lookup_ssl_issues():
    """Test retrieving remediation for expired cert and missing HTTPS."""
    expired_entry = get_remediation("ssl_certificate_expired")
    assert expired_entry is not None
    assert "certbot" in expired_entry["example"].lower()
    assert expired_entry["severity"] == "critical"

    no_https_entry = get_remediation("ssl_no_https")
    assert no_https_entry is not None
    assert "return 301" in no_https_entry["example"]
    assert no_https_entry["severity"] == "critical"


def test_remediation_text_formatting():
    """Test formatted multi-line remediation text."""
    text = get_remediation_text("Content-Security-Policy")
    assert "Issue:" in text
    assert "Why it matters:" in text
    assert "How to fix:" in text
    assert "Example" in text


def test_unknown_remediation():
    """Test fallback when an unknown check name is queried."""
    entry = get_remediation("non-existent-security-check")
    assert entry is None

    text = get_remediation_text("non-existent-security-check")
    assert "No specific remediation guidance" in text
