"""
VulnScan Lite — HTML Metadata Analyzer Module

Uses BeautifulSoup to passively inspect HTML documents.
Extracts:
  - <meta name="generator"> tag
  - <title> tag
  - <meta name="description"> tag
  - Script & stylesheet technology indicators (CDNs, common libraries)
  - Form count
  - External script count
  - HTTPS link presence

Safety & Limits:
  - Binary/non-HTML responses (e.g. PDF, images, archives) are detected via Content-Type and skipped safely.
  - JavaScript is never executed.
  - No external linked scripts or assets are downloaded.
  - Response size is capped to prevent memory exhaustion.
"""
from typing import Optional, List, Dict
from bs4 import BeautifulSoup
from urllib.parse import urlparse

from scanner.models import HTMLAnalysisResult

TECH_DOMAINS: dict[str, str] = {
    "jquery.com": "jQuery",
    "bootstrapcdn.com": "Bootstrap",
    "cloudflare.com": "Cloudflare",
    "googleapis.com": "Google APIs",
    "fontawesome.com": "Font Awesome",
    "cdn.jsdelivr.net": "jsDelivr CDN",
    "unpkg.com": "unpkg CDN",
    "react.dev": "React",
    "reactjs.org": "React",
    "angular.io": "Angular",
    "vuejs.org": "Vue.js",
    "cdn.shopify.com": "Shopify",
    "static.wixstatic.com": "Wix",
    "wp.com": "WordPress CDN",
    "tailwind": "Tailwind CSS",
}

NON_HTML_MIME_PREFIXES = (
    "image/",
    "video/",
    "audio/",
    "application/pdf",
    "application/zip",
    "application/x-",
    "application/octet-stream",
    "font/",
)


def is_html_content_type(content_type: Optional[str]) -> bool:
    """Check whether a Content-Type header indicates parseable HTML or text."""
    if not content_type:
        return True  # Assume HTML if not declared, but handle parsing safely
    ct_lower = content_type.lower()
    if any(ct_lower.startswith(prefix) for prefix in NON_HTML_MIME_PREFIXES):
        return False
    return "text/html" in ct_lower or "application/xhtml" in ct_lower or "text/plain" in ct_lower


def analyze_html(
    html_body: str,
    base_url: str = "",
    content_type: Optional[str] = None,
    truncated: bool = False,
) -> HTMLAnalysisResult:
    """
    Perform passive HTML structure and metadata analysis on a page body.

    Args:
        html_body: Raw text/HTML content of the response.
        base_url: The target base URL for domain comparison.
        content_type: HTTP response Content-Type header.
        truncated: Boolean indicating whether response was capped by size limits.

    Returns:
        HTMLAnalysisResult with metadata and technology indicators.
    """
    response_size = len(html_body.encode("utf-8", errors="ignore"))

    # If the response is an explicit non-HTML binary type, skip HTML parsing
    if content_type and not is_html_content_type(content_type):
        return HTMLAnalysisResult(
            is_html=False,
            content_type=content_type,
            truncated=truncated,
            response_size_bytes=response_size,
            category="HTML",
        )

    if not html_body or not html_body.strip():
        return HTMLAnalysisResult(
            is_html=True,
            content_type=content_type,
            truncated=truncated,
            response_size_bytes=0,
            category="HTML",
        )

    try:
        soup = BeautifulSoup(html_body, "lxml")
    except Exception:
        soup = BeautifulSoup(html_body, "html.parser")

    # <title>
    title_tag = soup.find("title")
    title: Optional[str] = title_tag.get_text(strip=True) if title_tag else None

    # <meta name="generator">
    generator_tag = soup.find("meta", attrs={"name": lambda x: x and x.lower() == "generator"})
    generator: Optional[str] = None
    if generator_tag and generator_tag.get("content"):
        generator = str(generator_tag["content"]).strip()

    # <meta name="description">
    desc_tag = soup.find("meta", attrs={"name": lambda x: x and x.lower() == "description"})
    description_meta: Optional[str] = None
    if desc_tag and desc_tag.get("content"):
        description_meta = str(desc_tag["content"]).strip()

    # Technology indicators & external scripts
    tech_indicators: List[str] = []
    external_scripts: int = 0
    base_parsed = urlparse(base_url)
    base_host = (base_parsed.hostname or "").lower()

    for script in soup.find_all("script", src=True):
        src = str(script.get("src", ""))
        src_parsed = urlparse(src)
        src_host = (src_parsed.hostname or "").lower()
        if src_host and src_host != base_host:
            external_scripts += 1
            for domain, tech_name in TECH_DOMAINS.items():
                if domain in src_host and tech_name not in tech_indicators:
                    tech_indicators.append(tech_name)
        elif not src_host:
            # Relative script
            for domain, tech_name in TECH_DOMAINS.items():
                if domain in src.lower() and tech_name not in tech_indicators:
                    tech_indicators.append(tech_name)

    # Insecure HTTP resource references detection (scripts, images, stylesheets, iframes, media)
    insecure_http_links: List[str] = []

    def _record_insecure_link(raw_val: str) -> None:
        val = raw_val.strip()
        if val.lower().startswith("http://"):
            try:
                p = urlparse(val)
                # Sanitize: keep scheme, host, and path only; omit sensitive query params and fragments
                clean = f"http://{p.netloc}{p.path}"
                if clean not in insecure_http_links and len(insecure_http_links) < 20:
                    insecure_http_links.append(clean)
            except Exception:
                pass

    for tag_name, attr_name in [("script", "src"), ("link", "href"), ("img", "src"), ("iframe", "src"), ("video", "src"), ("audio", "src"), ("source", "src")]:
        for el in soup.find_all(tag_name, attrs={attr_name: True}):
            _record_insecure_link(str(el.get(attr_name, "")))

    for link in soup.find_all("link", href=True):
        href = str(link.get("href", ""))
        for domain, tech_name in TECH_DOMAINS.items():
            if domain in href.lower() and tech_name not in tech_indicators:
                tech_indicators.append(tech_name)

    # Forms count
    form_count = len(soup.find_all("form"))

    # Check for outbound HTTPS links
    has_https_links = False
    for a in soup.find_all("a", href=True):
        href = str(a.get("href", "")).strip().lower()
        if href.startswith("https://"):
            has_https_links = True
            break

    return HTMLAnalysisResult(
        is_html=True,
        content_type=content_type,
        truncated=truncated,
        response_size_bytes=response_size,
        generator=generator,
        title=title,
        description_meta=description_meta,
        technology_indicators=tech_indicators,
        form_count=form_count,
        external_scripts=external_scripts,
        has_https_links=has_https_links,
        insecure_http_links=insecure_http_links,
        category="HTML",
    )

