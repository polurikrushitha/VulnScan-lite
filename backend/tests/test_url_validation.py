"""
VulnScan Lite — Tests for URL Validation and SSRF Protection

These tests do NOT make real network requests.
They test the validation logic in scanner/engine.py.
"""
import pytest
from unittest.mock import patch

from scanner.engine import validate_url, URLValidationError


# ---------------------------------------------------------------------------
# Valid URLs — should not raise
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("url", [
    "https://example.com",
    "https://example.com/path?q=1",
    "http://example.com",
    "https://subdomain.example.org",
    "https://example.com:8443/path",
])
def test_valid_urls(url):
    """Valid public URLs should pass validation without error."""
    mock_addr = [
        (None, None, None, None, ("93.184.216.34", 0))
    ]
    with patch("scanner.engine.socket.getaddrinfo", return_value=mock_addr):
        result = validate_url(url)
        assert result.strip() == url.strip()


# ---------------------------------------------------------------------------
# Invalid scheme
# ---------------------------------------------------------------------------

def test_invalid_scheme_ftp():
    with pytest.raises(URLValidationError, match="Invalid.*scheme"):
        validate_url("ftp://example.com")


def test_invalid_scheme_file():
    with pytest.raises(URLValidationError, match="Invalid.*scheme"):
        validate_url("file:///etc/passwd")


def test_no_scheme():
    with pytest.raises(URLValidationError):
        validate_url("example.com")


# ---------------------------------------------------------------------------
# SSRF Protection — private IP ranges
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("ip, description", [
    ("127.0.0.1", "IPv4 loopback"),
    ("10.0.0.1", "IPv4 private class A"),
    ("172.16.0.1", "IPv4 private class B"),
    ("192.168.1.1", "IPv4 private class C"),
    ("169.254.0.1", "IPv4 link-local"),
    ("::1", "IPv6 loopback"),
    ("fc00::1", "IPv6 private"),
    ("fe80::1", "IPv6 link-local"),
])
def test_ssrf_private_ip(ip, description):
    """Requests resolving to private IPs must be rejected."""
    mock_addr = [(None, None, None, None, (ip, 0))]
    with patch("scanner.engine.socket.getaddrinfo", return_value=mock_addr):
        with pytest.raises(URLValidationError, match="SSRF|private|reserved|internal"):
            validate_url("https://internal.example.com")


# ---------------------------------------------------------------------------
# SSRF Protection — blocked hostnames
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("url", [
    "http://localhost/",
    "http://localhost:8080/",
    "http://metadata.google.internal/",
    "http://169.254.169.254/",
])
def test_ssrf_blocked_hostnames(url):
    """Requests to known dangerous hostnames must be rejected."""
    with pytest.raises(URLValidationError):
        validate_url(url)


# ---------------------------------------------------------------------------
# DNS failure
# ---------------------------------------------------------------------------

def test_dns_failure():
    """DNS resolution failure should raise URLValidationError."""
    import socket
    with patch("scanner.engine.socket.getaddrinfo", side_effect=socket.gaierror("DNS failed")):
        with pytest.raises(URLValidationError, match="DNS resolution failed"):
            validate_url("https://this-domain-does-not-exist-xyz.com")
