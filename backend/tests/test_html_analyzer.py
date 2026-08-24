"""
VulnScan Lite — HTML Analyzer Unit Tests

Tests HTML metadata extraction, technology CDN detection, form counting,
non-HTML response handling, and size truncation.
"""
import pytest
from scanner.html_analyzer import analyze_html, is_html_content_type
from scanner.models import HTMLAnalysisResult


def test_is_html_content_type():
    """Test MIME type checker for HTML vs binary responses."""
    assert is_html_content_type("text/html; charset=UTF-8") is True
    assert is_html_content_type("text/html") is True
    assert is_html_content_type("application/xhtml+xml") is True
    assert is_html_content_type("image/png") is False
    assert is_html_content_type("application/pdf") is False
    assert is_html_content_type("application/zip") is False
    assert is_html_content_type("video/mp4") is False
    assert is_html_content_type(None) is True


def test_analyze_html_metadata():
    """Test extracting title, generator, description, and HTTPS links."""
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Security Portal — VulnScan</title>
        <meta name="generator" content="CustomFramework 2.0">
        <meta name="description" content="A comprehensive security dashboard.">
    </head>
    <body>
        <h1>Welcome</h1>
        <a href="https://example.com/login">Login Securely</a>
        <form action="/search" method="GET">
            <input type="text" name="q" />
            <button type="submit">Search</button>
        </form>
    </body>
    </html>
    """
    result = analyze_html(html, base_url="https://example.com", content_type="text/html")
    assert isinstance(result, HTMLAnalysisResult)
    assert result.is_html is True
    assert result.title == "Security Portal — VulnScan"
    assert result.generator == "CustomFramework 2.0"
    assert result.description_meta == "A comprehensive security dashboard."
    assert result.form_count == 1
    assert result.has_https_links is True


def test_analyze_technology_indicators():
    """Test detecting CDN-based JavaScript libraries."""
    html = """
    <html>
    <head>
        <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/react/18.2.0/umd/react.production.min.js"></script>
        <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
    </head>
    <body>
        <script src="/static/app.js"></script>
    </body>
    </html>
    """
    result = analyze_html(html, base_url="https://mywebsite.com")
    assert "jQuery" in result.technology_indicators
    assert "Cloudflare" in result.technology_indicators or "React" in result.technology_indicators
    assert "Bootstrap" in result.technology_indicators
    assert result.external_scripts >= 2


def test_non_html_binary_response():
    """Test that binary/PDF content types are not parsed as HTML."""
    fake_pdf = "%PDF-1.4 ... binary data ... %%EOF"
    result = analyze_html(
        fake_pdf,
        base_url="https://example.com/doc.pdf",
        content_type="application/pdf",
    )
    assert result.is_html is False
    assert result.title is None
    assert result.content_type == "application/pdf"
    assert result.form_count == 0


def test_truncated_response_flag():
    """Test that truncated response flags are preserved."""
    html = "<html><head><title>Truncated Page</title></head><body><h1>Hello</h1>"
    result = analyze_html(
        html,
        base_url="https://example.com",
        content_type="text/html",
        truncated=True,
    )
    assert result.is_html is True
    assert result.truncated is True
    assert result.title == "Truncated Page"


def test_insecure_http_links_extraction():
    """Test detecting and sanitizing insecure HTTP resource links."""
    html = """
    <html>
    <head>
        <script src="http://cdn.example.com/lib.js?token=secret123#frag"></script>
        <link rel="stylesheet" href="http://cdn.example.com/style.css">
    </head>
    <body>
        <img src="http://images.example.com/logo.png?auth=abc" />
        <iframe src="http://widgets.example.com/embed"></iframe>
        <a href="http://external-site.com">Normal Outbound Link</a>
    </body>
    </html>
    """
    result = analyze_html(html, base_url="https://example.com", content_type="text/html")
    assert len(result.insecure_http_links) >= 3
    # Verify sensitive query parameters are stripped
    assert "http://cdn.example.com/lib.js" in result.insecure_http_links
    assert "http://cdn.example.com/style.css" in result.insecure_http_links
    assert "http://images.example.com/logo.png" in result.insecure_http_links
    assert "secret123" not in "".join(result.insecure_http_links)

