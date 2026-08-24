"""
VulnScan Lite — Tests for Scoring Engine and Grade Calculation
"""
import pytest
from unittest.mock import MagicMock

from app.services.scoring import calculate_score, calculate_grade
from scanner.models import SSLResult, HeaderAnalysisResult, HeaderCheckResult


# ---------------------------------------------------------------------------
# Grade thresholds
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("score, expected_grade", [
    (100.0, "A"),
    (90.0, "A"),
    (89.9, "B+"),
    (80.0, "B+"),
    (79.9, "B"),
    (70.0, "B"),
    (69.9, "C"),
    (60.0, "C"),
    (59.9, "D"),
    (50.0, "D"),
    (49.9, "F"),
    (0.0, "F"),
])
def test_grade_thresholds(score, expected_grade):
    assert calculate_grade(score) == expected_grade


# ---------------------------------------------------------------------------
# Score clamping
# ---------------------------------------------------------------------------

def test_score_never_exceeds_100():
    """Score must be clamped at 100 even with many bonuses."""
    checks = [
        HeaderCheckResult(header_name="Content-Security-Policy", present=True, value="...", points=10, status="passed", description="", remediation="", category="Headers"),
        HeaderCheckResult(header_name="X-Frame-Options", present=True, value="...", points=10, status="passed", description="", remediation="", category="Headers"),
        HeaderCheckResult(header_name="Strict-Transport-Security", present=True, value="...", points=10, status="passed", description="", remediation="", category="Headers"),
        HeaderCheckResult(header_name="X-Content-Type-Options", present=True, value="...", points=5, status="passed", description="", remediation="", category="Headers"),
        HeaderCheckResult(header_name="Referrer-Policy", present=True, value="...", points=5, status="passed", description="", remediation="", category="Headers"),
        HeaderCheckResult(header_name="Permissions-Policy", present=True, value="...", points=5, status="passed", description="", remediation="", category="Headers"),
    ]
    header_result = MagicMock(spec=HeaderAnalysisResult)
    header_result.checks = checks

    ssl_result = MagicMock(spec=SSLResult)
    ssl_result.points = 20

    score = calculate_score(ssl_result=ssl_result, header_result=header_result)
    assert score == 100.0


def test_score_never_below_zero():
    """Score must be clamped at 0 even with many penalties."""
    checks = [
        HeaderCheckResult(header_name="Content-Security-Policy", present=False, value=None, points=-10, status="failed", description="", remediation="", category="Headers"),
        HeaderCheckResult(header_name="X-Frame-Options", present=False, value=None, points=-10, status="failed", description="", remediation="", category="Headers"),
        HeaderCheckResult(header_name="Strict-Transport-Security", present=False, value=None, points=-10, status="failed", description="", remediation="", category="Headers"),
    ]
    header_result = MagicMock(spec=HeaderAnalysisResult)
    header_result.checks = checks

    ssl_result = MagicMock(spec=SSLResult)
    ssl_result.points = -15

    score = calculate_score(ssl_result=ssl_result, header_result=header_result)
    assert score >= 0.0


# ---------------------------------------------------------------------------
# Individual scoring contributions
# ---------------------------------------------------------------------------

def test_all_headers_missing_no_ssl():
    """HTTP target with all headers missing should score below 50."""
    checks = [
        HeaderCheckResult(header_name="Content-Security-Policy", present=False, value=None, points=-10, status="failed", description="", remediation="", category="Headers"),
        HeaderCheckResult(header_name="X-Frame-Options", present=False, value=None, points=-10, status="failed", description="", remediation="", category="Headers"),
        HeaderCheckResult(header_name="Strict-Transport-Security", present=False, value=None, points=-10, status="failed", description="", remediation="", category="Headers"),
    ]
    header_result = MagicMock(spec=HeaderAnalysisResult)
    header_result.checks = checks

    ssl_result = MagicMock(spec=SSLResult)
    ssl_result.points = -10  # HTTP target

    score = calculate_score(ssl_result=ssl_result, header_result=header_result)
    # 50 baseline - 10 - 10 - 10 - 10 = 10
    assert score == 10.0
    assert calculate_grade(score) == "F"


def test_baseline_no_inputs():
    """No SSL or header results should return the baseline score."""
    score = calculate_score()
    assert score == 50.0
    assert calculate_grade(score) == "D"


# ---------------------------------------------------------------------------
# Risk Level classification
# ---------------------------------------------------------------------------

from app.services.scoring import calculate_risk_level

@pytest.mark.parametrize("score, expected_risk", [
    (100.0, "Excellent"),
    (90.0, "Excellent"),
    (89.9, "Good"),
    (80.0, "Good"),
    (75.0, "Moderate"),
    (60.0, "Moderate"),
    (59.9, "Needs Improvement"),
    (50.0, "Needs Improvement"),
    (49.9, "Poor"),
    (0.0, "Poor"),
    (None, "Unknown"),
])
def test_risk_level_thresholds(score, expected_risk):
    assert calculate_risk_level(score) == expected_risk

