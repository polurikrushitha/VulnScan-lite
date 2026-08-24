"""
VulnScan Lite — Tests for CMS Detection
"""
import pytest
from scanner.cms_detector import detect_cms


WORDPRESS_HTML = """
<html>
<head>
<meta name="generator" content="WordPress 6.4.2">
</head>
<body>
<link rel='stylesheet' href='/wp-content/themes/twentytwentyfour/style.css'>
</body>
</html>
"""

DRUPAL_HTML = """
<html>
<head>
<meta name="generator" content="Drupal 10 (https://www.drupal.org)">
</head>
<body>
<script src="/sites/default/files/js/drupal.js"></script>
</body>
</html>
"""

JOOMLA_HTML = """
<html>
<head>
<meta name="generator" content="Joomla! - Open Source Content Management">
</head>
<body>
<script src="/media/jui/js/jquery.min.js"></script>
</body>
</html>
"""

UNKNOWN_HTML = """
<html>
<head><title>Example</title></head>
<body><p>Hello World</p></body>
</html>
"""


def test_detect_wordpress_via_meta():
    result = detect_cms(WORDPRESS_HTML, {})
    assert result.detected is True
    assert result.cms_name == "WordPress"
    assert result.confidence == "high"
    assert "generator" in result.detection_source.lower()
    assert result.outdated_status == "Version detected; outdated status not determined."


def test_detect_wordpress_version():
    result = detect_cms(WORDPRESS_HTML, {})
    assert result.version == "6.4.2"
    assert result.version_exposed is True


def test_detect_drupal_via_meta():
    result = detect_cms(DRUPAL_HTML, {})
    assert result.detected is True
    assert result.cms_name == "Drupal"
    assert result.version == "10"


def test_detect_joomla_via_meta():
    result = detect_cms(JOOMLA_HTML, {})
    assert result.detected is True
    assert result.cms_name == "Joomla"


def test_no_cms_detected():
    result = detect_cms(UNKNOWN_HTML, {})
    assert result.detected is False
    assert result.cms_name is None
    assert result.outdated_status is None


def test_detect_via_x_powered_by():
    result = detect_cms("<html></html>", {"X-Powered-By": "PHP/8.1.0"})
    assert result.detected is True
    assert result.cms_name == "PHP"
    assert "X-Powered-By" in result.detection_source


def test_detect_via_body_pattern():
    html = "<html><body><a href='https://cdn.shopify.com/s/files/1/shop.js'>shop</a></body></html>"
    result = detect_cms(html, {})
    assert result.detected is True
    assert result.cms_name == "Shopify"
    assert "asset signature" in result.detection_source
