"""
VulnScan Lite — Security Scoring Engine

Scoring methodology:
====================

Starting point: 50 (neutral baseline)

SSL/TLS (max +20, min -15):
  - Valid certificate, >30 days remaining : +20
  - Valid certificate, <30 days remaining : +5
  - Expired certificate                   : -15
  - SSL error / verification failure      : -10
  - HTTP target (no HTTPS)                : -10

Required Security Headers (each ±10):
  - Content-Security-Policy  : +10 present / -10 missing
  - X-Frame-Options          : +10 present / -10 missing
  - Strict-Transport-Security: +10 present / -10 missing

Bonus Security Headers (each +5, no penalty):
  - X-Content-Type-Options   : +5 present
  - Referrer-Policy          : +5 present
  - Permissions-Policy       : +5 present

Final score is clamped to [0.0, 100.0].

Score Ranges & Risk Classification:
  90.0 – 100.0 : Excellent         (Grade A)
  80.0 – 89.9  : Good              (Grade B+)
  70.0 – 79.9  : Good              (Grade B)
  60.0 – 69.9  : Moderate          (Grade C)
  50.0 – 59.9  : Needs Improvement (Grade D)
  0.0  – 49.9  : Poor              (Grade F)
"""
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from scanner.models import SSLResult, HeaderAnalysisResult, CMSResult

BASELINE_SCORE = 50.0
MIN_SCORE = 0.0
MAX_SCORE = 100.0


def calculate_score(
    ssl_result: Optional["SSLResult"] = None,
    header_result: Optional["HeaderAnalysisResult"] = None,
    cms_result: Optional["CMSResult"] = None,
) -> float:
    """
    Compute the deterministic security score for a scan.

    Args:
        ssl_result:     SSL/TLS inspection result.
        header_result:  Security header analysis result.
        cms_result:     CMS detection result (currently informational only).

    Returns:
        A float score clamped to [0.0, 100.0].
    """
    score = BASELINE_SCORE

    # --- SSL/TLS contribution ---
    if ssl_result is not None:
        score += ssl_result.points

    # --- Header contributions ---
    if header_result is not None:
        for check in header_result.checks:
            score += check.points

    # Clamp to [0, 100]
    return float(max(MIN_SCORE, min(MAX_SCORE, score)))


def calculate_grade(score: float) -> str:
    """
    Convert a numeric score to a letter grade.

    Args:
        score: Security score in [0.0, 100.0].

    Returns:
        Grade string: A, B+, B, C, D, or F.
    """
    if score >= 90:
        return "A"
    elif score >= 80:
        return "B+"
    elif score >= 70:
        return "B"
    elif score >= 60:
        return "C"
    elif score >= 50:
        return "D"
    else:
        return "F"


def calculate_risk_level(score: Optional[float]) -> str:
    """
    Convert a numeric score to an executive risk rating label.

    Args:
        score: Security score in [0.0, 100.0].

    Returns:
        Risk label: 'Excellent', 'Good', 'Moderate', 'Needs Improvement', 'Poor', or 'Unknown'.
    """
    if score is None:
        return "Unknown"
    if score >= 90:
        return "Excellent"
    elif score >= 80:
        return "Good"
    elif score >= 60:
        return "Moderate"
    elif score >= 50:
        return "Needs Improvement"
    else:
        return "Poor"

