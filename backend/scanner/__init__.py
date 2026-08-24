"""
VulnScan Lite — Scanner Package

Passive security analysis modules:
  - engine.py       : Orchestrates all scanner modules with SSRF protection and safety limits
  - headers.py      : Security header analysis (CSP, X-Frame-Options, HSTS, etc.)
  - ssl_check.py    : SSL/TLS certificate inspection via Python standard library ssl
  - cms_detector.py : Passive CMS detection via HTML metadata and headers
  - html_analyzer.py: HTML metadata, technology scripts, and structural analysis
  - models.py       : Structured dataclasses for scanner inputs, outputs, checks, and findings
"""
from scanner.models import (
    ScanEngineResult,
    SSLResult,
    HeaderAnalysisResult,
    HeaderCheckResult,
    CMSResult,
    HTMLAnalysisResult,
    HTTPInfo,
    ServerInfo,
    FindingItem,
    SecurityCheckItem,
)
from scanner.engine import run_scan, validate_url, URLValidationError
from scanner.headers import analyze_headers
from scanner.ssl_check import check_ssl
from scanner.cms_detector import detect_cms
from scanner.html_analyzer import analyze_html

__all__ = [
    "run_scan",
    "validate_url",
    "URLValidationError",
    "analyze_headers",
    "check_ssl",
    "detect_cms",
    "analyze_html",
    "ScanEngineResult",
    "SSLResult",
    "HeaderAnalysisResult",
    "HeaderCheckResult",
    "CMSResult",
    "HTMLAnalysisResult",
    "HTTPInfo",
    "ServerInfo",
    "FindingItem",
    "SecurityCheckItem",
]
