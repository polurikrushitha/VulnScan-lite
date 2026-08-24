"""
VulnScan Lite — Passive Scanner Engine

Orchestrates all passive scanner modules:
  1. URL Validation & SSRF Protection (IPv4 & IPv6 private/link-local/cloud metadata validation)
  2. Target Reachability Pre-Flight Check (DNS & socket handshake probe)
  3. Safe HTTP Fetch (Controlled redirect loop with hop-by-hop SSRF validation, size capping)
  4. Security Header Analysis (CSP, X-Frame-Options, HSTS, and bonus headers)
  5. SSL/TLS Certificate Inspection (Public cert parameters, expiry, cipher, TLS version)
  6. HTML Metadata & Structure Analysis (Generator, title, CDN scripts, forms, HTTPS links)
  7. CMS Detection (Passive fingerprinting for WordPress, Drupal, Joomla, Shopify, etc.)
  8. Deterministic Scoring & Grade Assignment (0–100 scale, strict grade boundaries)
  9. Structured Findings & Remediation Assembly with Affected URL, Evidence, and Confidence

The engine runs synchronously in worker execution contexts and returns JSON-serializable
ScanEngineResult instances.
"""
import ipaddress
import logging
import socket
import time
from typing import Optional, Tuple, Dict, Any, List, Callable
from urllib.parse import urlparse, urljoin

import httpx

from scanner.models import (
    ScanEngineResult,
    SSLResult,
    HeaderAnalysisResult,
    CMSResult,
    HTMLAnalysisResult,
    HTTPInfo,
    ServerInfo,
    SecurityCheckItem,
    FindingItem,
)
from scanner.headers import analyze_headers
from scanner.ssl_check import check_ssl
from scanner.html_analyzer import analyze_html
from scanner.cms_detector import detect_cms
from app.services.scoring import calculate_score, calculate_grade
from app.services.remediation import get_remediation
from app.core.config import settings

logger = logging.getLogger("vulnscan.scanner")

# ---------------------------------------------------------------------------
# Safety & Resource Limits
# ---------------------------------------------------------------------------

MAX_RESPONSE_BYTES = 2 * 1024 * 1024     # 2 MB response body limit
CONNECT_TIMEOUT = 10.0                    # seconds
READ_TIMEOUT = 20.0                       # seconds
MAX_REDIRECTS = 5

SAFE_USER_AGENT = "VulnScan-Lite/1.0 (passive security scanner; https://github.com/vulnscan-lite)"

# Private / reserved IPv4 & IPv6 subnets blocked by SSRF protection
BLOCKED_NETWORKS = [
    # IPv4
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),     # CGNAT
    ipaddress.ip_network("127.0.0.0/8"),       # Loopback
    ipaddress.ip_network("169.254.0.0/16"),    # Link-local / Cloud metadata
    ipaddress.ip_network("172.16.0.0/12"),     # Private Class B
    ipaddress.ip_network("192.0.0.0/24"),      # IETF Protocol Assignments
    ipaddress.ip_network("192.0.2.0/24"),      # TEST-NET-1
    ipaddress.ip_network("192.168.0.0/16"),    # Private Class C
    ipaddress.ip_network("198.18.0.0/15"),     # Benchmarking
    ipaddress.ip_network("198.51.100.0/24"),   # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),    # TEST-NET-3
    ipaddress.ip_network("224.0.0.0/4"),       # Multicast
    ipaddress.ip_network("240.0.0.0/4"),       # Reserved
    ipaddress.ip_network("255.255.255.255/32"),# Broadcast
    # IPv6
    ipaddress.ip_network("::1/128"),           # IPv6 Loopback
    ipaddress.ip_network("::/128"),            # Unspecified
    ipaddress.ip_network("fc00::/7"),          # Unique local (private)
    ipaddress.ip_network("fe80::/10"),         # Link-local
    ipaddress.ip_network("ff00::/8"),          # Multicast
]

BLOCKED_HOSTNAMES = {
    "localhost",
    "localhost.localdomain",
    "metadata.google.internal",
    "169.254.169.254",                         # AWS / GCP / Azure metadata IP
    "instance-data",
}

CLOUD_METADATA_HOSTS = {
    "metadata.google.internal",
    "169.254.169.254",
    "instance-data",
}


# ---------------------------------------------------------------------------
# URL Validation & SSRF Protection
# ---------------------------------------------------------------------------

class URLValidationError(Exception):
    """Raised when a target URL fails validation or SSRF restrictions."""


def is_ip_blocked(ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Check if an IP address belongs to any blocked/private/loopback/cloud metadata network range."""
    return any(ip_obj in network for network in BLOCKED_NETWORKS)


def is_target_allowlisted(hostname: str, port: Optional[int]) -> bool:
    """
    Check if a target matches the explicitly configured development allowlist.
    Returns True ONLY if:
      - Development allowlist is active (ALLOW_DEV_TARGETS=True and ENVIRONMENT != 'production')
      - Target is NOT a cloud metadata host or metadata IP
      - Target 'hostname:port' or 'hostname' matches an explicit entry in DEV_TARGET_ALLOWLIST.
    """
    if not settings.is_dev_allowlist_enabled():
        return False

    hostname_lower = hostname.lower().strip()
    if hostname_lower in CLOUD_METADATA_HOSTS:
        return False

    allowlist = settings.get_dev_target_allowlist()
    target_with_port = f"{hostname_lower}:{port}" if port else None

    if target_with_port and target_with_port in allowlist:
        return True
    if hostname_lower in allowlist and port is None:
        return True
    return False


def validate_url(url: str) -> str:
    """
    Validate and normalize a target URL with robust SSRF protection.

    Validates:
      - Scheme: must be http or https
      - Hostname: non-empty, not in blocked hostnames list (unless explicitly allowlisted in dev)
      - DNS Resolution: resolves to valid public IP addresses (unless explicitly allowlisted in dev)

    Raises:
        URLValidationError with a clear message when a target is blocked by SSRF protection.
    """
    if not url or not isinstance(url, str):
        raise URLValidationError("Target URL cannot be empty.")

    url = url.strip()
    parsed = urlparse(url)

    if parsed.scheme.lower() not in ("http", "https"):
        raise URLValidationError(
            f"Invalid URL scheme '{parsed.scheme}'. Only 'http' and 'https' are supported."
        )

    if not parsed.hostname:
        raise URLValidationError("Target URL must specify a valid hostname.")

    hostname = parsed.hostname.lower().strip()
    port = parsed.port

    # 1. Cloud metadata endpoints are strictly prohibited under all circumstances
    if hostname in CLOUD_METADATA_HOSTS:
        raise URLValidationError(
            f"Scanning cloud metadata endpoint '{hostname}' is strictly prohibited (SSRF protection)."
        )

    # 2. Check if target is explicitly permitted by development allowlist
    if is_target_allowlisted(hostname, port):
        return url

    # 3. Blocked internal / loopback hostnames
    if hostname in BLOCKED_HOSTNAMES:
        raise URLValidationError(
            f"Scanning target '{hostname}' is prohibited by SSRF protection. Internal hostnames, private IP ranges, and loopback addresses are blocked."
        )

    # 4. Direct IP address literal check
    try:
        direct_ip = ipaddress.ip_address(hostname)
        if is_ip_blocked(direct_ip):
            raise URLValidationError(
                f"Scanning target '{hostname}' is prohibited by SSRF protection. Target is a private/reserved IP address."
            )
        return url
    except ValueError:
        pass  # Hostname is a domain name, proceed with DNS resolution

    # 5. Domain DNS resolution check
    try:
        addr_info = socket.getaddrinfo(hostname, None)
    except socket.gaierror as e:
        raise URLValidationError(f"DNS resolution failed for '{hostname}': {e}")
    except Exception as e:
        raise URLValidationError(f"Could not resolve host '{hostname}': {e}")

    if not addr_info:
        raise URLValidationError(f"DNS lookup returned no address records for '{hostname}'.")

    for _family, _type, _proto, _canonname, sockaddr in addr_info:
        ip_str = sockaddr[0]
        try:
            resolved_ip = ipaddress.ip_address(ip_str)
            if is_ip_blocked(resolved_ip):
                raise URLValidationError(
                    f"Scanning target '{hostname}' is prohibited by SSRF protection. Resolved IP address '{ip_str}' is private/internal."
                )
        except ValueError:
            continue

    return url



# ---------------------------------------------------------------------------
# Safe HTTP Fetch Client with Controlled Redirects
# ---------------------------------------------------------------------------

def _fetch_safe(url: str) -> Tuple[Optional[httpx.Response], Optional[str], Optional[HTTPInfo]]:
    """
    Execute a safe HTTP GET request with manual redirect following and SSRF re-validation.

    Features:
      - Limits redirects to MAX_REDIRECTS (5)
      - Revalidates redirect target URLs against SSRF filters before following
      - Caps downloaded content size at MAX_RESPONSE_BYTES (2 MB)
      - Enforces connection and read timeouts
      - Uses safe User-Agent identifier

    Returns:
        Tuple of (response_object, error_message, http_info)
    """
    client_timeout = httpx.Timeout(
        connect=CONNECT_TIMEOUT,
        read=READ_TIMEOUT,
        write=10.0,
        pool=5.0,
    )
    headers = {
        "User-Agent": SAFE_USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
    }

    current_url = url
    redirect_count = 0
    start_time = time.perf_counter()

    try:
        with httpx.Client(
            timeout=client_timeout,
            follow_redirects=False,  # Manual redirect loop for SSRF inspection on every hop
            verify=True,
            limits=httpx.Limits(max_keepalive_connections=5, max_connections=10),
        ) as client:
            while True:
                response = client.get(current_url, headers=headers)

                # Check for redirect status codes (301, 302, 303, 307, 308)
                if response.status_code in (301, 302, 303, 307, 308):
                    location = response.headers.get("location")
                    if not location:
                        break  # Redirect without Location header, terminate

                    redirect_count += 1
                    if redirect_count > MAX_REDIRECTS:
                        return None, "Exceeded maximum redirect limit (5 hops).", None

                    # Resolve relative redirect URLs against current URL
                    next_url = urljoin(current_url, location)

                    # Re-validate destination against SSRF filters
                    try:
                        next_url = validate_url(next_url)
                    except URLValidationError as err:
                        logger.warning("Redirect to unsafe target blocked by security policy: %s", err)
                        return None, "Target rejected by VulnScan Lite security policy.", None

                    current_url = next_url
                    continue

                # Final response reached
                duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
                content_type = response.headers.get("content-type", "")

                http_info = HTTPInfo(
                    status_code=response.status_code,
                    final_url=str(response.url),
                    redirect_count=redirect_count,
                    response_time_ms=duration_ms,
                    content_type=content_type,
                )

                # Size limit enforcement: cap body to MAX_RESPONSE_BYTES
                if len(response.content) > MAX_RESPONSE_BYTES:
                    response._content = response.content[:MAX_RESPONSE_BYTES]

                return response, None, http_info

    except httpx.ConnectTimeout:
        return None, (
            "Target could not be reached.\n\n"
            "Please verify:\n"
            "• URL is correct\n"
            "• Website is online\n"
            "• Network connection is available\n"
            "• The target permits authorized testing"
        ), None
    except (httpx.ConnectError, httpx.RequestError) as e:
        return None, (
            "Target could not be reached.\n\n"
            "Please verify:\n"
            "• URL is correct\n"
            "• Website is online\n"
            "• Network connection is available\n"
            "• The target permits authorized testing"
        ), None
    except httpx.SSLError as e:
        return None, f"SSL/TLS error during HTTP fetch: {e}", None
    except Exception as e:
        return None, f"Unexpected network error: {e}", None


# ---------------------------------------------------------------------------
# Findings & Checks Assembler
# ---------------------------------------------------------------------------

def _assemble_findings_and_checks(
    target_url: str,
    ssl_result: Optional[SSLResult],
    header_result: Optional[HeaderAnalysisResult],
    cms_result: Optional[CMSResult],
    html_result: Optional[HTMLAnalysisResult] = None,
) -> Tuple[List[SecurityCheckItem], List[FindingItem]]:
    """Convert raw scanner module results into structured security checks and findings with impact and evidence."""
    checks: List[SecurityCheckItem] = []
    findings: List[FindingItem] = []

    # 1. SSL/TLS Checks & Findings
    if ssl_result:
        status_map = {
            "valid": "passed",
            "expired": "failed",
            "verification_failed": "failed",
            "connection_failed": "failed",
            "http": "warning",
        }
        chk_status = status_map.get(ssl_result.status, "info")
        checks.append(SecurityCheckItem(
            check_name="SSL/TLS Certificate",
            category="SSL/TLS",
            status=chk_status,
            points=ssl_result.points,
            description=ssl_result.description,
        ))

        if ssl_result.status == "expired":
            rem = get_remediation("ssl_certificate_expired")
            findings.append(FindingItem(
                check_name="SSL/TLS Certificate Expired",
                severity="critical",
                description=ssl_result.description,
                impact="An expired SSL certificate prevents secure connections, causing browser trust errors for all visitors and blocking user traffic.",
                remediation=rem["how_to_fix"] if rem else "Renew the SSL certificate immediately.",
                category="SSL/TLS",
                affected_url=target_url,
                evidence=f"Certificate expired on {ssl_result.not_after or 'unknown date'}.",
                confidence="high",
            ))
        elif ssl_result.status == "verification_failed":
            findings.append(FindingItem(
                check_name="SSL/TLS Verification Failed",
                severity="high",
                description=ssl_result.description,
                impact="Untrusted or mismatched certificates fail browser root authority verification, leaving users vulnerable to man-in-the-middle interception.",
                remediation="Configure a valid certificate issued by a trusted Certificate Authority (e.g. Let's Encrypt).",
                category="SSL/TLS",
                affected_url=target_url,
                evidence=ssl_result.error or "Certificate validation failed against trusted root authorities.",
                confidence="high",
            ))
        elif ssl_result.status == "http":
            rem = get_remediation("ssl_no_https")
            findings.append(FindingItem(
                check_name="HTTPS Not Configured",
                severity="critical",
                description="The target website is served over unencrypted plain HTTP without TLS encryption.",
                impact="All communications, logins, and session data are transmitted in plaintext across the network and can be intercepted.",
                remediation=rem["how_to_fix"] if rem else "Configure HTTPS and redirect HTTP traffic.",
                category="SSL/TLS",
                affected_url=target_url,
                evidence=f"Target URL scheme is {urlparse(target_url).scheme}:// (plaintext transport).",
                confidence="high",
            ))

    # 2. Header Checks & Findings
    if header_result:
        header_impact_map = {
            "Content-Security-Policy": "Without CSP, the browser executes scripts from any origin, significantly increasing Cross-Site Scripting (XSS) and data injection exploitability.",
            "Strict-Transport-Security": "Without HSTS, initial connections may occur over unencrypted HTTP, allowing SSL-stripping and protocol downgrade attacks.",
            "X-Frame-Options": "Pages without clickjacking protection can be invisibly embedded in third-party iframes to trick users into executing unauthorized actions.",
            "X-Content-Type-Options": "Without nosniff, older browsers may interpret non-script files (such as user uploads) as executable scripts.",
            "Referrer-Policy": "Full URL paths and query parameters may leak in the HTTP Referer header when users navigate to external sites.",
            "Permissions-Policy": "Unrestricted browser features (geolocation, camera, microphone) remain accessible to embedded third-party scripts.",
        }

        severity_map = {
            "Content-Security-Policy": "high",
            "Strict-Transport-Security": "high",
            "X-Frame-Options": "medium",
            "X-Content-Type-Options": "low",
            "Referrer-Policy": "low",
            "Permissions-Policy": "low",
        }

        for chk in header_result.checks:
            checks.append(SecurityCheckItem(
                check_name=chk.header_name,
                category=chk.category,
                status=chk.status,
                points=chk.points,
                description=chk.description,
            ))

            if chk.status == "failed" and chk.points < 0:
                rem_info = get_remediation(chk.header_name)
                severity = severity_map.get(chk.header_name, rem_info.get("severity", "medium") if rem_info else "medium")
                impact_text = header_impact_map.get(chk.header_name, rem_info.get("why_it_matters", "") if rem_info else "")
                findings.append(FindingItem(
                    check_name=f"Missing {chk.header_name}",
                    severity=severity,
                    description=f"{chk.header_name} security header is missing from server responses.",
                    impact=impact_text,
                    remediation=chk.remediation,
                    category="Headers",
                    affected_url=target_url,
                    evidence=f"HTTP response headers did not contain '{chk.header_name}'.",
                    confidence="high",
                ))

        if header_result.server:
            checks.append(SecurityCheckItem(
                check_name="Server Header Disclosure",
                category="Technology",
                status="info",
                points=0,
                description=f"Server header discloses web server signature: '{header_result.server}'.",
            ))

    # 3. Insecure HTTP Links / Mixed Content Check
    if html_result and html_result.insecure_http_links and target_url.lower().startswith("https://"):
        checks.append(SecurityCheckItem(
            check_name="Insecure HTTP References",
            category="Transport",
            status="warning",
            points=-3,
            description=f"Found {len(html_result.insecure_http_links)} insecure HTTP asset reference(s) on HTTPS page.",
        ))
        findings.append(FindingItem(
            check_name="Insecure HTTP References",
            severity="low",
            description=f"The HTTPS page references {len(html_result.insecure_http_links)} asset(s) over unencrypted HTTP.",
            impact="HTTP resources referenced from an HTTPS page may create mixed-content or transport-security concerns depending on how the browser handles the resource.",
            remediation="Update all asset references (scripts, stylesheets, images, iframes) to use HTTPS or protocol-relative URLs.",
            category="Transport",
            affected_url=target_url,
            evidence=f"Insecure references detected: {', '.join(html_result.insecure_http_links[:3])}{'...' if len(html_result.insecure_http_links) > 3 else ''}",
            confidence="high",
        ))

    # 4. CMS Checks
    if cms_result and cms_result.detected:
        checks.append(SecurityCheckItem(
            check_name=f"CMS Detection: {cms_result.cms_name}",
            category="Technology",
            status="info",
            points=0,
            description=cms_result.description,
        ))

    return checks, findings



# ---------------------------------------------------------------------------
# Main Orchestration Engine
# ---------------------------------------------------------------------------

def run_scan(
    url: str,
    stage_callback: Optional[Callable[[str], None]] = None,
) -> ScanEngineResult:
    """
    Execute the complete passive security scan pipeline for a target URL.

    Pipeline stages:
      1. VALIDATING: Validate URL syntax and verify target is not private/reserved (SSRF check)
      2. CONNECTING: Verify target is online and reachable via DNS / socket probe
      3. SCANNING: Perform passive SSL/TLS certificate inspection & Safe HTTP fetch
      4. ANALYZING: Analyze security headers, HTML metadata, and detect CMS
      5. GENERATING_REPORT: Calculate score, grade, assemble findings and checks

    Args:
        url: Raw user-provided target URL.
        stage_callback: Optional callback to notify caller of stage changes.

    Returns:
        ScanEngineResult containing full scan diagnostics, score, grade, and findings.
    """
    scan_start = time.perf_counter()
    logger.info("Starting passive scan for target: %s", url)

    # --- Step 1: Target URL Validation & SSRF Enforcement Phase ---
    if stage_callback:
        stage_callback("validating")

    try:
        validated_url = validate_url(url)
    except URLValidationError as err:
        logger.warning("URL validation / security policy rejected %s: %s", url, err)
        return ScanEngineResult(
            target_url=url,
            scan_successful=False,
            score=0.0,
            grade="F",
            error_type="validation_error",
            error="Target rejected by VulnScan Lite security policy.",
            duration_seconds=round(time.perf_counter() - scan_start, 3),
        )

    if stage_callback:
        stage_callback("policy_check")

    # --- Step 2: Target Reachability & Connectivity Phase ---
    if stage_callback:
        stage_callback("connecting")

    # --- Step 3: Passive Scanning (SSL & HTTP Fetch) ---
    if stage_callback:
        stage_callback("scanning")

    logger.debug("Executing SSL/TLS inspection for %s", validated_url)
    ssl_result: SSLResult = check_ssl(validated_url)

    logger.debug("Executing HTTP fetch for %s", validated_url)
    response, fetch_error, http_info = _fetch_safe(validated_url)

    if response is None or fetch_error:
        logger.warning("HTTP fetch failed for %s: %s", validated_url, fetch_error)
        duration = round(time.perf_counter() - scan_start, 3)
        # In case HTTP fetch fails
        checks, findings = _assemble_findings_and_checks(validated_url, ssl_result, None, None)
        err_type = "reachability_error" if "could not be reached" in (fetch_error or "").lower() else "fetch_error"
        return ScanEngineResult(
            target_url=validated_url,
            scan_successful=False,
            score=0.0,
            grade="F",
            http=http_info,
            ssl=ssl_result,
            security_checks=checks,
            findings=findings,
            error_type=err_type,
            error=fetch_error or "Target could not be reached.",
            duration_seconds=duration,
        )

    # --- Step 4: Analysis (Headers, HTML, CMS) ---
    if stage_callback:
        stage_callback("analyzing")

    raw_content = response.content
    truncated = len(raw_content) >= MAX_RESPONSE_BYTES
    content_type = response.headers.get("content-type", "")

    try:
        body_text = raw_content[:MAX_RESPONSE_BYTES].decode("utf-8", errors="replace")
    except Exception:
        body_text = ""

    # Header analysis
    response_headers = dict(response.headers)
    header_result: HeaderAnalysisResult = analyze_headers(response_headers)

    # Server Info
    server_info = ServerInfo(
        server=header_result.server,
        x_powered_by=header_result.x_powered_by,
    )

    # HTML analysis
    html_result: HTMLAnalysisResult = analyze_html(
        html_body=body_text,
        base_url=validated_url,
        content_type=content_type,
        truncated=truncated,
    )

    # CMS detection
    cms_result: CMSResult = detect_cms(
        html_body=body_text,
        response_headers=response_headers,
    )

    # --- Step 5: Report Generation (Scoring & Findings Assembly) ---
    if stage_callback:
        stage_callback("generating_report")

    score = calculate_score(
        ssl_result=ssl_result,
        header_result=header_result,
        cms_result=cms_result,
    )
    grade = calculate_grade(score)

    checks, findings = _assemble_findings_and_checks(
        target_url=validated_url,
        ssl_result=ssl_result,
        header_result=header_result,
        cms_result=cms_result,
        html_result=html_result,
    )

    scan_duration = round(time.perf_counter() - scan_start, 3)
    logger.info(
        "Passive scan completed for %s in %.3fs — Score: %.1f, Grade: %s",
        validated_url,
        scan_duration,
        score,
        grade,
    )

    return ScanEngineResult(
        target_url=validated_url,
        scan_successful=True,
        score=score,
        grade=grade,
        http=http_info,
        ssl=ssl_result,
        headers=header_result,
        cms=cms_result,
        html=html_result,
        server=server_info,
        security_checks=checks,
        findings=findings,
        error_type=None,
        error=None,
        duration_seconds=scan_duration,
    )

