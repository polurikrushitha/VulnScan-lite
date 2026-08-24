"""
VulnScan Lite — SSL/TLS Inspection Unit Tests

Tests certificate inspection, expiration parsing, verification failure handling,
and plain HTTP behavior without performing live network attacks.
"""
import ssl
from unittest.mock import patch, MagicMock
import pytest

from scanner.ssl_check import check_ssl, _parse_dn
from scanner.models import SSLResult


def test_parse_dn():
    """Test converting SSL distinguished name tuple to a formatted string."""
    dn_tuple = (
        (("countryName", "US"),),
        (("organizationName", "Example Corp"),),
        (("commonName", "example.com"),),
    )
    res = _parse_dn(dn_tuple)
    assert "countryName=US" in res
    assert "organizationName=Example Corp" in res
    assert "commonName=example.com" in res


def test_http_target_no_ssl():
    """Test that a plain HTTP target returns an appropriate non-TLS status."""
    result = check_ssl("http://example.com")
    assert isinstance(result, SSLResult)
    assert result.is_https is False
    assert result.connection_successful is False
    assert result.certificate_valid is False
    assert result.status == "http"
    assert result.points == -10
    assert "plain HTTP" in result.description


@patch("socket.create_connection")
@patch("ssl.create_default_context")
def test_valid_ssl_certificate(mock_ctx_factory, mock_conn):
    """Test inspecting a valid SSL certificate with >30 days remaining."""
    mock_ctx = MagicMock()
    mock_ctx_factory.return_value = mock_ctx
    mock_ssock = MagicMock()
    mock_ctx.wrap_socket.return_value.__enter__.return_value = mock_ssock

    mock_ssock.version.return_value = "TLSv1.3"
    mock_ssock.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
    mock_ssock.getpeercert.return_value = {
        "subject": ((("commonName", "example.com"),),),
        "issuer": ((("organizationName", "DigiCert Inc"),),),
        "notBefore": "Jan  1 00:00:00 2026 GMT",
        "notAfter": "Dec 31 23:59:59 2030 GMT",
    }

    result = check_ssl("https://example.com")
    assert result.is_https is True
    assert result.connection_successful is True
    assert result.certificate_valid is True
    assert result.certificate_expired is False
    assert result.status == "valid"
    assert result.tls_version == "TLSv1.3"
    assert "TLS_AES_256_GCM_SHA384" in result.cipher
    assert "example.com" in result.subject
    assert "DigiCert Inc" in result.issuer
    assert result.points == 20
    assert result.days_until_expiry is not None and result.days_until_expiry > 30


@patch("socket.create_connection")
@patch("ssl.create_default_context")
def test_expired_ssl_certificate(mock_ctx_factory, mock_conn):
    """Test inspecting an expired SSL certificate."""
    mock_ctx = MagicMock()
    mock_ctx_factory.return_value = mock_ctx
    mock_ssock = MagicMock()
    mock_ctx.wrap_socket.return_value.__enter__.return_value = mock_ssock

    mock_ssock.version.return_value = "TLSv1.2"
    mock_ssock.cipher.return_value = ("ECDHE-RSA-AES128-GCM-SHA256", "TLSv1.2", 128)
    mock_ssock.getpeercert.return_value = {
        "subject": ((("commonName", "expired.example.com"),),),
        "issuer": ((("organizationName", "Test CA"),),),
        "notBefore": "Jan  1 00:00:00 2020 GMT",
        "notAfter": "Jan  1 00:00:00 2021 GMT",
    }

    result = check_ssl("https://expired.example.com")
    assert result.is_https is True
    assert result.connection_successful is True
    assert result.certificate_expired is True
    assert result.certificate_valid is False
    assert result.status == "expired"
    assert result.points == -15
    assert "expired" in result.description.lower()


@patch("socket.create_connection")
@patch("ssl.create_default_context")
def test_ssl_verification_failure(mock_ctx_factory, mock_conn):
    """Test handling of an untrusted or self-signed certificate error."""
    mock_ctx = MagicMock()
    mock_ctx_factory.return_value = mock_ctx
    mock_ctx.wrap_socket.side_effect = ssl.SSLCertVerificationError(
        1, "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: self-signed certificate"
    )

    result = check_ssl("https://self-signed.example.com")
    assert result.is_https is True
    assert result.connection_successful is False
    assert result.certificate_valid is False
    assert result.status == "verification_failed"
    assert result.points == -15
    assert "could not be verified" in result.description.lower() or "verification failed" in (result.error or "").lower()


@patch("socket.create_connection")
@patch("ssl.create_default_context")
def test_ssl_connection_timeout(mock_ctx_factory, mock_conn):
    """Test handling socket timeouts during SSL handshake."""
    import socket
    mock_conn.side_effect = socket.timeout("timed out")

    result = check_ssl("https://timeout.example.com")
    assert result.is_https is True
    assert result.connection_successful is False
    assert result.status == "connection_failed"
    assert "timed out" in (result.error or "").lower()
