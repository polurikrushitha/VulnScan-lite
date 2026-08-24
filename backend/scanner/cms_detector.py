"""
VulnScan Lite — CMS Detection Module

Passively detects common Content Management Systems and web application platforms by inspecting:
  1. HTML <meta name="generator"> tags
  2. HTTP response headers (e.g. X-Powered-By)
  3. Safe public HTML body markers (e.g. asset paths and script signatures)

Supported platforms:
  - WordPress
  - Drupal
  - Joomla
  - Shopify
  - Wix
  - Squarespace
  - Ghost
  - Typo3
  - Magento
  - PrestaShop

Technical & Safety Principles:
  - Purely passive inspection: no exploitation, no brute forcing, no admin probing.
  - Versions are only captured when explicitly exposed by the website in public metadata or headers.
  - Outdated status is NOT claimed or fabricated without an authoritative version feed;
    returns "Version detected; outdated status not determined." when a version is present.
"""
import re
from typing import Optional, Dict
from bs4 import BeautifulSoup

from scanner.models import CMSResult

# ---------------------------------------------------------------------------
# CMS Signature Definitions
# ---------------------------------------------------------------------------

GENERATOR_PATTERNS: list[dict] = [
    {"cms": "WordPress", "pattern": r"wordpress\s*([0-9.]+)?", "flags": re.IGNORECASE},
    {"cms": "Drupal",    "pattern": r"drupal\s*([0-9.]+)?",    "flags": re.IGNORECASE},
    {"cms": "Joomla",   "pattern": r"joomla[!]?\s*([0-9.]+)?", "flags": re.IGNORECASE},
    {"cms": "Ghost",     "pattern": r"ghost\s*([0-9.]+)?",      "flags": re.IGNORECASE},
    {"cms": "Typo3",     "pattern": r"typo3\s*([0-9.]+)?",      "flags": re.IGNORECASE},
]

HEADER_PATTERNS: list[dict] = [
    {"cms": "WordPress",  "pattern": r"wp",             "flags": re.IGNORECASE},
    {"cms": "Drupal",     "pattern": r"drupal",          "flags": re.IGNORECASE},
    {"cms": "PHP",        "pattern": r"php/([0-9.]+)?",  "flags": re.IGNORECASE},
    {"cms": "Shopify",    "pattern": r"shopify",         "flags": re.IGNORECASE},
    {"cms": "Magento",    "pattern": r"magento",         "flags": re.IGNORECASE},
    {"cms": "PrestaShop", "pattern": r"prestashop",      "flags": re.IGNORECASE},
]

BODY_PATTERNS: list[dict] = [
    {"cms": "WordPress",   "pattern": r"/wp-content/",          "flags": re.IGNORECASE},
    {"cms": "WordPress",   "pattern": r"/wp-includes/",         "flags": re.IGNORECASE},
    {"cms": "Drupal",      "pattern": r"/sites/default/files/", "flags": re.IGNORECASE},
    {"cms": "Drupal",      "pattern": r"drupal\.js",            "flags": re.IGNORECASE},
    {"cms": "Joomla",      "pattern": r"/media/jui/",            "flags": re.IGNORECASE},
    {"cms": "Joomla",      "pattern": r"/components/com_",       "flags": re.IGNORECASE},
    {"cms": "Shopify",     "pattern": r"cdn\.shopify\.com",     "flags": re.IGNORECASE},
    {"cms": "Wix",         "pattern": r"static\.wixstatic\.com","flags": re.IGNORECASE},
    {"cms": "Squarespace", "pattern": r"squarespace\.com",      "flags": re.IGNORECASE},
    {"cms": "Ghost",       "pattern": r"/ghost/api/",           "flags": re.IGNORECASE},
    {"cms": "Typo3",       "pattern": r"typo3temp/",            "flags": re.IGNORECASE},
    {"cms": "Magento",     "pattern": r"Mage\.Cookies",         "flags": re.IGNORECASE},
    {"cms": "PrestaShop",  "pattern": r"prestashop",            "flags": re.IGNORECASE},
]


def _extract_version(text: str, pattern: str, flags: int) -> Optional[str]:
    """Extract version string from text matching regex capturing groups."""
    match = re.search(pattern, text, flags)
    if match and match.lastindex and match.lastindex >= 1:
        extracted = match.group(1)
        if extracted and extracted.strip():
            return extracted.strip()
    return None


def detect_cms(
    html_body: str,
    response_headers: Dict[str, str],
    soup: Optional[BeautifulSoup] = None,
) -> CMSResult:
    """
    Perform passive CMS detection on the response body and headers.

    Args:
        html_body: Raw HTML response body string.
        response_headers: HTTP response headers dictionary.
        soup: Optional pre-parsed BeautifulSoup object to reuse.

    Returns:
        CMSResult with detected CMS, version, confidence, and explanation.
    """
    if not html_body and not response_headers:
        return CMSResult(
            detected=False,
            description="No response content available for CMS detection.",
            category="CMS",
        )

    if soup is None and html_body:
        try:
            soup = BeautifulSoup(html_body, "lxml")
        except Exception:
            soup = BeautifulSoup(html_body, "html.parser")

    cms_name: Optional[str] = None
    version: Optional[str] = None
    detection_source: Optional[str] = None
    confidence: str = "none"

    # 1. Inspect <meta name="generator"> tag (Highest confidence for version exposure)
    if soup:
        generator_tag = soup.find("meta", attrs={"name": re.compile(r"^generator$", re.I)})
        if generator_tag and generator_tag.get("content"):
            gen_val = str(generator_tag["content"]).strip()
            for pdef in GENERATOR_PATTERNS:
                if re.search(pdef["pattern"], gen_val, pdef["flags"]):
                    cms_name = pdef["cms"]
                    version = _extract_version(gen_val, pdef["pattern"], pdef["flags"])
                    detection_source = f"generator meta tag ({gen_val})"
                    confidence = "high"
                    break

    # 2. Inspect HTTP headers (e.g. X-Powered-By)
    if not cms_name:
        normalised_headers = {k.lower(): v for k, v in response_headers.items()}
        powered_by = normalised_headers.get("x-powered-by", "")
        if powered_by:
            for pdef in HEADER_PATTERNS:
                if re.search(pdef["pattern"], powered_by, pdef["flags"]):
                    cms_name = pdef["cms"]
                    version = _extract_version(powered_by, pdef["pattern"], pdef["flags"])
                    detection_source = f"X-Powered-By header ({powered_by})"
                    confidence = "medium"
                    break

    # 3. Inspect HTML body asset paths and signatures
    if not cms_name and html_body:
        for pdef in BODY_PATTERNS:
            if re.search(pdef["pattern"], html_body, pdef["flags"]):
                cms_name = pdef["cms"]
                detection_source = "HTML body asset signature"
                confidence = "medium"
                break

    if not cms_name:
        return CMSResult(
            detected=False,
            description="No known CMS signature detected via passive inspection.",
            category="CMS",
        )

    # Determine honest outdated status without guessing
    version_exposed = version is not None
    outdated_status = (
        "Version detected; outdated status not determined." if version_exposed else None
    )

    ver_display = f"v{version}" if version else "version not exposed"
    description = (
        f"{cms_name} detected ({ver_display}) via {detection_source} "
        f"[Confidence: {confidence}]."
    )

    return CMSResult(
        detected=True,
        cms_name=cms_name,
        version=version,
        detection_source=detection_source,
        confidence=confidence,
        version_exposed=version_exposed,
        outdated_status=outdated_status,
        description=description,
        category="CMS",
    )
