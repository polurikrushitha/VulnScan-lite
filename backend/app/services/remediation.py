"""
VulnScan Lite — Remediation Engine

For every known failed security check, provides:
  - issue description
  - why it matters
  - how to fix it
  - example remediation (labelled as guidance, not a universal prescription)

All remediation text is educational and passive — no exploit guidance.
"""
from typing import Dict, Optional

# ---------------------------------------------------------------------------
# Remediation database
# ---------------------------------------------------------------------------
# Key: normalised check name (lowercase, stripped)

REMEDIATION_DATABASE: Dict[str, Dict[str, str]] = {

    "content-security-policy": {
        "issue": "Content-Security-Policy header is missing.",
        "why_it_matters": (
            "Without CSP, browsers may load scripts or resources from unintended "
            "origins, making Cross-Site Scripting (XSS) attacks more effective. "
            "An attacker who finds an XSS vulnerability can execute arbitrary "
            "JavaScript in victims' browsers."
        ),
        "how_to_fix": (
            "Add a Content-Security-Policy header to your web server or application. "
            "Start with a strict policy and relax it as needed. "
            "Use report-uri or report-to to monitor violations before enforcing."
        ),
        "example": (
            "# Example Nginx configuration (adjust directives to your app's needs):\n"
            "add_header Content-Security-Policy \""
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "object-src 'none'; "
            "frame-ancestors 'none';"
            "\" always;\n\n"
            "# Example Apache configuration:\n"
            "Header always set Content-Security-Policy \""
            "default-src 'self'; script-src 'self'; object-src 'none';\""
        ),
        "severity": "high",
    },

    "x-frame-options": {
        "issue": "X-Frame-Options header is missing.",
        "why_it_matters": (
            "Without X-Frame-Options, your page can be embedded in an iframe on "
            "an attacker's website. This enables clickjacking attacks, where users "
            "are tricked into clicking on invisible buttons that perform actions "
            "on your site."
        ),
        "how_to_fix": (
            "Add an X-Frame-Options header with value DENY or SAMEORIGIN. "
            "Alternatively, use the Content-Security-Policy frame-ancestors directive "
            "for more fine-grained control."
        ),
        "example": (
            "# Nginx:\n"
            "add_header X-Frame-Options \"SAMEORIGIN\" always;\n\n"
            "# Apache:\n"
            "Header always set X-Frame-Options \"SAMEORIGIN\"\n\n"
            "# CSP alternative (more flexible):\n"
            "add_header Content-Security-Policy \"frame-ancestors 'self';\" always;"
        ),
        "severity": "medium",
    },

    "strict-transport-security": {
        "issue": "Strict-Transport-Security (HSTS) header is missing.",
        "why_it_matters": (
            "Without HSTS, browsers may connect over HTTP before being redirected "
            "to HTTPS, exposing users to protocol downgrade attacks and man-in-the-middle "
            "interception, especially on their first visit or after clearing cookies."
        ),
        "how_to_fix": (
            "Add an HSTS header. Only do this once you are confident that your site "
            "serves all content over HTTPS — enabling HSTS incorrectly can make your "
            "site inaccessible until it expires."
        ),
        "example": (
            "# Nginx:\n"
            "add_header Strict-Transport-Security "
            "\"max-age=31536000; includeSubDomains\" always;\n\n"
            "# Apache:\n"
            "Header always set Strict-Transport-Security "
            "\"max-age=31536000; includeSubDomains\"\n\n"
            "# Note: Consider adding 'preload' only after careful review of "
            "https://hstspreload.org requirements."
        ),
        "severity": "high",
    },

    "x-content-type-options": {
        "issue": "X-Content-Type-Options header is missing.",
        "why_it_matters": (
            "Without this header, older browsers may 'sniff' the MIME type of a "
            "response, potentially interpreting non-script content as executable "
            "scripts, leading to cross-site scripting vulnerabilities."
        ),
        "how_to_fix": "Set the header to 'nosniff'.",
        "example": (
            "# Nginx:\n"
            "add_header X-Content-Type-Options \"nosniff\" always;\n\n"
            "# Apache:\n"
            "Header always set X-Content-Type-Options \"nosniff\""
        ),
        "severity": "low",
    },

    "referrer-policy": {
        "issue": "Referrer-Policy header is missing.",
        "why_it_matters": (
            "Without a Referrer-Policy, browsers may send full URL referrer information "
            "to third-party sites, leaking internal URL structures, session tokens in "
            "query strings, or other sensitive path information."
        ),
        "how_to_fix": "Set an appropriate Referrer-Policy based on your privacy requirements.",
        "example": (
            "# Nginx:\n"
            "add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;\n\n"
            "# Apache:\n"
            "Header always set Referrer-Policy \"strict-origin-when-cross-origin\""
        ),
        "severity": "low",
    },

    "permissions-policy": {
        "issue": "Permissions-Policy header is missing.",
        "why_it_matters": (
            "Without Permissions-Policy, browser features such as camera, microphone, "
            "and geolocation may be accessible to third-party scripts embedded on the page."
        ),
        "how_to_fix": "Restrict browser features to only those your application requires.",
        "example": (
            "# Nginx:\n"
            "add_header Permissions-Policy \"camera=(), microphone=(), geolocation=()\" always;\n\n"
            "# Apache:\n"
            "Header always set Permissions-Policy \"camera=(), microphone=(), geolocation=()\""
        ),
        "severity": "low",
    },

    "ssl_certificate_expired": {
        "issue": "SSL/TLS certificate is expired.",
        "why_it_matters": (
            "An expired certificate causes browser trust errors for all visitors, prevents encrypted communication, "
            "and signals that certificate lifecycle management processes have failed."
        ),
        "how_to_fix": "Renew the SSL certificate immediately using your Certificate Authority or Let's Encrypt.",
        "example": (
            "# Renew with Let's Encrypt / Certbot:\n"
            "certbot renew\n\n"
            "# Enable auto-renewal timer:\n"
            "systemctl enable --now certbot.timer"
        ),
        "severity": "critical",
    },

    "ssl_verification_failed": {
        "issue": "SSL/TLS certificate verification failed.",
        "why_it_matters": (
            "Self-signed, mismatched, or untrusted certificates fail root authority verification in standard web browsers, "
            "leaving users susceptible to man-in-the-middle interception."
        ),
        "how_to_fix": "Install a valid, publicly trusted certificate matching your exact domain name.",
        "example": (
            "# Obtain a trusted certificate using Certbot:\n"
            "certbot certonly --webroot -w /var/www/html -d yourdomain.com"
        ),
        "severity": "high",
    },

    "ssl_no_https": {
        "issue": "Site does not use HTTPS.",
        "why_it_matters": (
            "All traffic between the user and the server is transmitted in plaintext, "
            "exposing credentials, session tokens, and personal data to interception "
            "by anyone on the network path."
        ),
        "how_to_fix": "Obtain an SSL certificate and configure your server to serve all content over HTTPS.",
        "example": (
            "# Free certificate with Let's Encrypt:\n"
            "certbot --nginx -d yourdomain.com\n\n"
            "# Redirect HTTP to HTTPS in Nginx:\n"
            "server {\n"
            "    listen 80;\n"
            "    server_name yourdomain.com;\n"
            "    return 301 https://$host$request_uri;\n"
            "}"
        ),
        "severity": "critical",
    },

    "insecure-http-references": {
        "issue": "Insecure HTTP resources referenced on an HTTPS page.",
        "why_it_matters": (
            "HTTP resources referenced from an HTTPS page may create mixed-content or transport-security concerns "
            "depending on how the browser handles the resource."
        ),
        "how_to_fix": "Update all asset references (scripts, stylesheets, images, iframes) to use HTTPS or relative paths.",
        "example": (
            "<!-- Before (insecure): -->\n"
            "<script src=\"http://cdn.example.com/lib.js\"></script>\n\n"
            "<!-- After (secure): -->\n"
            "<script src=\"https://cdn.example.com/lib.js\"></script>"
        ),
        "severity": "low",
    },

    "server-header-exposed": {
        "issue": "Server banner header exposes web server technology.",
        "why_it_matters": (
            "Exposed server banners provide reconnaissance metadata to automated scanners and attackers researching stack-specific CVEs."
        ),
        "how_to_fix": "Disable or obscure the Server response header in your web server configuration.",
        "example": (
            "# Nginx (disable version in server token):\n"
            "server_tokens off;\n\n"
            "# Apache:\n"
            "ServerTokens Prod\n"
            "ServerSignature Off"
        ),
        "severity": "info",
    },

    "x-powered-by-exposed": {
        "issue": "X-Powered-By header exposes backend runtime framework.",
        "why_it_matters": (
            "Exposing technology runtimes (e.g. Express, PHP, ASP.NET) assists attackers in fingerprinting application components."
        ),
        "how_to_fix": "Configure your application framework to disable the X-Powered-By header.",
        "example": (
            "# Express.js:\n"
            "app.disable('x-powered-by');\n\n"
            "# PHP (php.ini):\n"
            "expose_php = Off"
        ),
        "severity": "info",
    },
}


def get_remediation(check_name: str) -> Optional[Dict[str, str]]:
    """
    Retrieve remediation guidance for a specific check.

    Args:
        check_name: The name of the failed security check (case-insensitive).

    Returns:
        Dict with keys: issue, why_it_matters, how_to_fix, example, severity.
        None if no remediation entry exists.
    """
    key = check_name.lower().strip().replace(" ", "-")
    return REMEDIATION_DATABASE.get(key)


def get_remediation_text(check_name: str) -> str:
    """
    Return a formatted remediation string suitable for embedding in reports.

    Args:
        check_name: The name of the failed security check.

    Returns:
        Multi-line remediation text string.
    """
    entry = get_remediation(check_name)
    if not entry:
        return f"No specific remediation guidance available for '{check_name}'."

    lines = [
        f"Issue: {entry['issue']}",
        "",
        f"Why it matters: {entry['why_it_matters']}",
        "",
        f"How to fix: {entry['how_to_fix']}",
        "",
        "Example (this is guidance — adjust to your specific server and application):",
        entry["example"],
    ]
    return "\n".join(lines)
