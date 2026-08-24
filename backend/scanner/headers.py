"""
VulnScan Lite — Security Header Analysis Module

Performs passive analysis of HTTP response headers against standard security baselines.

Required security headers (scored ±10 points):
  - Content-Security-Policy   (+10 present / -10 missing)
  - X-Frame-Options           (+10 present / -10 missing)
  - Strict-Transport-Security (+10 present / -10 missing)

Additional informational headers (rewarded +5, no penalty for missing):
  - X-Content-Type-Options    (+5 present / 0 missing)
  - Referrer-Policy           (+5 present / 0 missing)
  - Permissions-Policy        (+5 present / 0 missing)

All analysis is purely passive — inspecting returned response headers only.
No attack payloads or active probes are sent.
"""
from typing import Dict, Optional
from scanner.models import HeaderCheckResult, HeaderAnalysisResult

# ---------------------------------------------------------------------------
# Required security headers — each contributes ±10 points
# ---------------------------------------------------------------------------

REQUIRED_HEADERS: list[dict] = [
    {
        "name": "Content-Security-Policy",
        "description": (
            "Content-Security-Policy (CSP) restricts which sources a browser is "
            "allowed to load or execute, helping prevent Cross-Site Scripting (XSS) "
            "and data injection attacks."
        ),
        "remediation": (
            "Add a Content-Security-Policy header to your server responses.\n"
            "Example (Nginx):\n"
            "  add_header Content-Security-Policy \"default-src 'self'; "
            "script-src 'self'; object-src 'none';\" always;\n"
            "Note: Guidance only. Adjust directives to match your application's actual resource needs."
        ),
        "points_present": 10,
        "points_missing": -10,
    },
    {
        "name": "X-Frame-Options",
        "description": (
            "X-Frame-Options helps reduce clickjacking risk by instructing the browser "
            "whether the page may be rendered within a frame, iframe, embed, or object."
        ),
        "remediation": (
            "Add an X-Frame-Options header to your server responses.\n"
            "Example (Nginx):\n"
            "  add_header X-Frame-Options \"SAMEORIGIN\" always;\n"
            "Note: Guidance only. Alternatively, configure the CSP frame-ancestors directive."
        ),
        "points_present": 10,
        "points_missing": -10,
    },
    {
        "name": "Strict-Transport-Security",
        "description": (
            "HTTP Strict Transport Security (HSTS) instructs browsers to always "
            "communicate over HTTPS, mitigating protocol downgrade attacks and cookie hijacking."
        ),
        "remediation": (
            "Add a Strict-Transport-Security header to your HTTPS responses.\n"
            "Example (Nginx):\n"
            "  add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;\n"
            "Note: Guidance only. Enable HSTS only after ensuring your entire domain supports HTTPS."
        ),
        "points_present": 10,
        "points_missing": -10,
    },
]

# ---------------------------------------------------------------------------
# Additional informational headers — rewarded but not penalised
# ---------------------------------------------------------------------------

BONUS_HEADERS: list[dict] = [
    {
        "name": "X-Content-Type-Options",
        "description": (
            "X-Content-Type-Options: nosniff prevents browsers from MIME-sniffing "
            "the response body away from the declared content-type, reducing drive-by download risks."
        ),
        "remediation": (
            "Add an X-Content-Type-Options header to your server responses.\n"
            "Example (Nginx):\n"
            "  add_header X-Content-Type-Options \"nosniff\" always;\n"
            "Note: Guidance only."
        ),
        "points_present": 5,
        "points_missing": 0,
    },
    {
        "name": "Referrer-Policy",
        "description": (
            "Referrer-Policy controls how much referrer information is included "
            "with requests made from your site, preventing sensitive URL data leakage."
        ),
        "remediation": (
            "Add a Referrer-Policy header to your server responses.\n"
            "Example (Nginx):\n"
            "  add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;\n"
            "Note: Guidance only."
        ),
        "points_present": 5,
        "points_missing": 0,
    },
    {
        "name": "Permissions-Policy",
        "description": (
            "Permissions-Policy allows site owners to restrict browser features and APIs "
            "(such as camera, microphone, and geolocation) available to the page."
        ),
        "remediation": (
            "Add a Permissions-Policy header to your server responses.\n"
            "Example (Nginx):\n"
            "  add_header Permissions-Policy \"camera=(), microphone=(), geolocation=()\" always;\n"
            "Note: Guidance only."
        ),
        "points_present": 5,
        "points_missing": 0,
    },
]


def analyze_headers(response_headers: Dict[str, str]) -> HeaderAnalysisResult:
    """
    Perform passive security header analysis on a dict of HTTP response headers.

    Args:
        response_headers: Dictionary of HTTP response headers (case-insensitive keys).

    Returns:
        HeaderAnalysisResult with individual check results, raw headers, and server tech.
    """
    normalised = {k.lower(): v for k, v in response_headers.items()}
    checks: list[HeaderCheckResult] = []

    # 1. Required security headers (±10)
    for header_def in REQUIRED_HEADERS:
        name = header_def["name"]
        key = name.lower()
        present = key in normalised
        value: Optional[str] = normalised.get(key)
        points = header_def["points_present"] if present else header_def["points_missing"]
        status = "passed" if present else "failed"

        checks.append(HeaderCheckResult(
            header_name=name,
            present=present,
            value=value,
            points=points,
            status=status,
            description=header_def["description"],
            remediation=header_def["remediation"] if not present else "",
            category="Headers",
        ))

    # 2. Bonus security headers (+5 / 0)
    for header_def in BONUS_HEADERS:
        name = header_def["name"]
        key = name.lower()
        present = key in normalised
        value = normalised.get(key)
        points = header_def["points_present"] if present else header_def["points_missing"]
        status = "passed" if present else "info"

        checks.append(HeaderCheckResult(
            header_name=name,
            present=present,
            value=value,
            points=points,
            status=status,
            description=header_def["description"],
            remediation=header_def["remediation"] if not present else "",
            category="Headers",
        ))

    return HeaderAnalysisResult(
        checks=checks,
        raw_headers=dict(response_headers),
        server=normalised.get("server"),
        x_powered_by=normalised.get("x-powered-by"),
    )
