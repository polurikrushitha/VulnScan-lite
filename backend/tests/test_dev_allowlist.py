"""
VulnScan Lite — Tests for Development-Only Target Allowlist & SSRF Protection

Validates:
1. Default state: SSRF protection is enabled by default and blocks all local/internal/private targets.
2. Production mode: Always blocks localhost, 127.0.0.1, private IPs, link-local, and cloud metadata even if ALLOW_DEV_TARGETS is set.
3. Development mode with ALLOW_DEV_TARGETS=True:
   - Permitted: ONLY explicitly allowlisted targets (e.g. localhost:3000, localhost:8080, 127.0.0.1:3000, 127.0.0.1:8080).
   - Blocked: Non-allowlisted local targets (e.g. localhost:9000, 127.0.0.1:5000, 192.168.1.1, 10.0.0.1).
   - Blocked: Cloud metadata endpoints (169.254.169.254, metadata.google.internal) under ALL circumstances.
4. Clear error messages when SSRF blocks a target.
"""
import pytest
from unittest.mock import patch

from app.core.config import settings
from scanner.engine import validate_url, URLValidationError


# ---------------------------------------------------------------------------
# 1. Default State (ALLOW_DEV_TARGETS = False)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("url", [
    "http://localhost:3000",
    "http://localhost:8080",
    "http://127.0.0.1:3000",
    "http://127.0.0.1:8080",
    "http://localhost/",
    "http://127.0.0.1/",
    "http://10.0.0.1/",
    "http://172.16.0.1/",
    "http://192.168.1.1/",
    "http://169.254.169.254/",
    "http://metadata.google.internal/",
])
def test_default_state_blocks_all_internal_targets(url):
    """By default, ALLOW_DEV_TARGETS is False, so all internal/local targets must be blocked."""
    with patch.object(settings, "ALLOW_DEV_TARGETS", False):
        with patch.object(settings, "ENVIRONMENT", "development"):
            with pytest.raises(URLValidationError, match="SSRF protection"):
                validate_url(url)


# ---------------------------------------------------------------------------
# 2. Production Mode (ENVIRONMENT = "production")
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("url", [
    "http://localhost:3000",
    "http://localhost:8080",
    "http://127.0.0.1:3000",
    "http://127.0.0.1:8080",
    "http://10.0.0.5:8000",
    "http://192.168.0.10:3000",
    "http://169.254.169.254/",
    "http://metadata.google.internal/",
])
def test_production_mode_always_blocks_internal_targets(url):
    """In production, even if ALLOW_DEV_TARGETS is True, all internal targets must be blocked."""
    with patch.object(settings, "ENVIRONMENT", "production"):
        with patch.object(settings, "ALLOW_DEV_TARGETS", True):
            with patch.object(settings, "DEV_TARGET_ALLOWLIST", "localhost:3000,localhost:8080,127.0.0.1:3000,127.0.0.1:8080"):
                with pytest.raises(URLValidationError, match="SSRF protection"):
                    validate_url(url)


# ---------------------------------------------------------------------------
# 3. Development Mode with Explicit Allowlist
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("url", [
    "http://localhost:3000",
    "http://localhost:3000/rest/products/search",
    "http://localhost:8080",
    "http://localhost:8080/app",
    "http://127.0.0.1:3000",
    "http://127.0.0.1:8080",
])
def test_dev_mode_permits_explicitly_allowlisted_targets(url):
    """In development mode with ALLOW_DEV_TARGETS=True, allowlisted targets pass validation."""
    with patch.object(settings, "ENVIRONMENT", "development"):
        with patch.object(settings, "ALLOW_DEV_TARGETS", True):
            with patch.object(settings, "DEV_TARGET_ALLOWLIST", "localhost:3000,localhost:8080,127.0.0.1:3000,127.0.0.1:8080"):
                result = validate_url(url)
                assert result.strip() == url.strip()


@pytest.mark.parametrize("url", [
    "http://localhost:9000",
    "http://localhost:5000",
    "http://127.0.0.1:5000",
    "http://127.0.0.1:9090",
    "http://192.168.1.1:3000",
    "http://10.0.0.1:8080",
    "http://172.16.1.1/",
])
def test_dev_mode_blocks_non_allowlisted_internal_targets(url):
    """In dev mode with allowlist active, local targets not in the allowlist must STILL be blocked."""
    with patch.object(settings, "ENVIRONMENT", "development"):
        with patch.object(settings, "ALLOW_DEV_TARGETS", True):
            with patch.object(settings, "DEV_TARGET_ALLOWLIST", "localhost:3000,localhost:8080,127.0.0.1:3000,127.0.0.1:8080"):
                with pytest.raises(URLValidationError, match="SSRF protection"):
                    validate_url(url)


# ---------------------------------------------------------------------------
# 4. Cloud Metadata Endpoints are NEVER allowed
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("url", [
    "http://169.254.169.254/",
    "http://169.254.169.254/latest/meta-data/",
    "http://metadata.google.internal/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://instance-data/",
])
def test_cloud_metadata_strictly_blocked_under_all_conditions(url):
    """Cloud metadata endpoints must be blocked even if someone attempts to configure them in allowlist."""
    with patch.object(settings, "ENVIRONMENT", "development"):
        with patch.object(settings, "ALLOW_DEV_TARGETS", True):
            with patch.object(settings, "DEV_TARGET_ALLOWLIST", "169.254.169.254,metadata.google.internal,instance-data,localhost:3000"):
                with pytest.raises(URLValidationError, match="cloud metadata endpoint|SSRF protection"):
                    validate_url(url)


# ---------------------------------------------------------------------------
# 5. Clear SSRF Error Messages
# ---------------------------------------------------------------------------

def test_clear_ssrf_error_message():
    """Verify that blocked targets produce clear, descriptive SSRF rejection messages."""
    with patch.object(settings, "ALLOW_DEV_TARGETS", False):
        try:
            validate_url("http://localhost:8080")
        except URLValidationError as err:
            assert "SSRF protection" in str(err)
            assert "blocked" in str(err).lower() or "prohibited" in str(err).lower()
