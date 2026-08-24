"""
VulnScan Lite — SSL/TLS Inspection Module

Uses Python's built-in `ssl` and `socket` modules to perform passive certificate inspection.
Inspects:
  - Whether an HTTPS connection can be established
  - Certificate validity (not expired, trusted chain)
  - Certificate subject and issuer
  - TLS version negotiated
  - Cipher suite in use
  - Certificate expiry date and days remaining
  - Explicit certificate state: valid, expired, verification_failed, connection_failed, http

This module does NOT:
  - Disable certificate verification to force a connection
  - Perform TLS downgrade attacks
  - Enumerate ciphers aggressively
  - Exploit TLS vulnerabilities

For HTTP targets, the result clearly indicates that the target uses HTTP rather than calling
the certificate "invalid".
"""
import ssl
import socket
from datetime import datetime, timezone
from typing import Optional, Tuple
from urllib.parse import urlparse

from scanner.models import SSLResult

CONNECT_TIMEOUT = 10.0


def _parse_dn(dn_tuple: tuple) -> str:
    """Convert an ssl distinguished-name tuple/dict to a readable string."""
    parts = []
    for entry in dn_tuple:
        for k, v in entry:
            parts.append(f"{k}={v}")
    return ", ".join(parts)


def check_ssl(url: str) -> SSLResult:
    """
    Perform passive SSL/TLS inspection for the given URL.

    Args:
        url: The target URL (http:// or https://).

    Returns:
        SSLResult populated with certificate and TLS information.
    """
    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    hostname = parsed.hostname
    port = parsed.port or (443 if scheme == "https" else 80)

    # HTTP targets — no TLS connection attempted
    if scheme != "https":
        return SSLResult(
            is_https=False,
            connection_successful=False,
            certificate_valid=False,
            certificate_expired=False,
            status="http",
            error=None,
            points=-10,
            description="Target is served over plain HTTP with no TLS encryption.",
            category="SSL/TLS",
        )

    if not hostname:
        return SSLResult(
            is_https=True,
            connection_successful=False,
            certificate_valid=False,
            certificate_expired=False,
            status="connection_failed",
            error="Missing target hostname for SSL inspection.",
            points=-10,
            description="Unable to parse hostname for TLS connection.",
            category="SSL/TLS",
        )

    # HTTPS target — secure TLS context with strict certificate verification
    ctx = ssl.create_default_context()
    result = SSLResult(
        is_https=True,
        connection_successful=False,
        certificate_valid=False,
        certificate_expired=False,
        status="unknown",
        points=0,
        description="",
        category="SSL/TLS",
    )

    try:
        with socket.create_connection((hostname, port), timeout=CONNECT_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                result.connection_successful = True
                result.tls_version = ssock.version()
                cipher_info = ssock.cipher()
                if cipher_info:
                    result.cipher = f"{cipher_info[0]} ({cipher_info[1]})"

                cert = ssock.getpeercert()
                if cert:
                    # Subject & Issuer
                    subject = cert.get("subject", ())
                    result.subject = _parse_dn(subject) if subject else None

                    issuer = cert.get("issuer", ())
                    result.issuer = _parse_dn(issuer) if issuer else None

                    # Validity dates
                    not_before_str = cert.get("notBefore")
                    not_after_str = cert.get("notAfter")
                    result.not_before = not_before_str
                    result.not_after = not_after_str

                    if not_after_str:
                        try:
                            not_after_dt = datetime.strptime(
                                not_after_str, "%b %d %H:%M:%S %Y %Z"
                            ).replace(tzinfo=timezone.utc)
                            now = datetime.now(timezone.utc)
                            delta = not_after_dt - now
                            days_remaining = delta.days
                            result.days_until_expiry = days_remaining

                            if days_remaining < 0:
                                result.certificate_expired = True
                                result.certificate_valid = False
                                result.status = "expired"
                                result.points = -15
                                result.description = (
                                    f"SSL certificate expired {abs(days_remaining)} days ago."
                                )
                            elif days_remaining < 30:
                                result.certificate_expired = False
                                result.certificate_valid = True
                                result.status = "valid"
                                result.points = 5
                                result.description = (
                                    f"SSL certificate is valid but expires soon ({days_remaining} days remaining)."
                                )
                            else:
                                result.certificate_expired = False
                                result.certificate_valid = True
                                result.status = "valid"
                                result.points = 20
                                result.description = (
                                    f"SSL certificate is valid and trusted ({days_remaining} days remaining)."
                                )
                        except ValueError:
                            result.certificate_valid = True
                            result.status = "valid"
                            result.points = 10
                            result.description = "SSL certificate is valid (expiry date format not parseable)."
                    else:
                        result.certificate_valid = True
                        result.status = "valid"
                        result.points = 10
                        result.description = "SSL certificate is valid."

    except ssl.SSLCertVerificationError as e:
        result.connection_successful = False
        result.certificate_valid = False
        result.status = "verification_failed"
        err_msg = getattr(e, "verify_message", str(e))
        result.error = f"Certificate verification failed: {err_msg}"
        result.points = -15
        result.description = (
            "TLS certificate verification failed. The certificate may be self-signed, "
            "issued by an untrusted Certificate Authority, or hostname mismatch."
        )

    except ssl.SSLError as e:
        result.connection_successful = False
        result.certificate_valid = False
        result.status = "connection_failed"
        result.error = f"SSL/TLS handshake error: {str(e)}"
        result.points = -10
        result.description = "An SSL/TLS protocol error occurred while establishing the connection."

    except socket.timeout:
        result.connection_successful = False
        result.status = "connection_failed"
        result.error = "TLS connection timed out."
        result.points = -5
        result.description = "The TLS connection timed out."

    except (socket.gaierror, OSError) as e:
        result.connection_successful = False
        result.status = "connection_failed"
        result.error = f"Connection error: {str(e)}"
        result.points = -5
        result.description = "Could not establish a network connection for TLS inspection."

    return result
