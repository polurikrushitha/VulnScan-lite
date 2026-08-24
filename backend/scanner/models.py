"""
VulnScan Lite — Scanner Data Models

Typed dataclasses representing the structured output of each scanner module.
These models are JSON-serializable and easily converted to database records.
"""
from dataclasses import dataclass, field, asdict
from typing import Optional, List, Dict, Any


@dataclass
class HeaderCheckResult:
    """Result of a single security header check."""
    header_name: str
    present: bool
    value: Optional[str]
    points: int
    status: str                         # "passed" | "failed" | "info"
    description: str
    remediation: str
    category: str = "Headers"


@dataclass
class HeaderAnalysisResult:
    """Aggregated result of all security header checks."""
    checks: List[HeaderCheckResult] = field(default_factory=list)
    raw_headers: Dict[str, str] = field(default_factory=dict)
    server: Optional[str] = None
    x_powered_by: Optional[str] = None


@dataclass
class SSLResult:
    """Result of SSL/TLS inspection."""
    is_https: bool
    connection_successful: bool
    certificate_valid: bool
    certificate_expired: bool
    status: str = "unknown"             # "valid" | "expired" | "verification_failed" | "connection_failed" | "http"
    subject: Optional[str] = None
    issuer: Optional[str] = None
    tls_version: Optional[str] = None
    cipher: Optional[str] = None
    not_before: Optional[str] = None
    not_after: Optional[str] = None
    days_until_expiry: Optional[int] = None
    error: Optional[str] = None
    points: int = 0
    description: str = ""
    category: str = "SSL/TLS"


@dataclass
class CMSResult:
    """Result of CMS detection."""
    detected: bool
    cms_name: Optional[str] = None
    version: Optional[str] = None
    detection_source: Optional[str] = None
    confidence: str = "none"            # "none" | "low" | "medium" | "high"
    version_exposed: bool = False
    outdated_status: Optional[str] = None
    description: str = ""
    category: str = "CMS"


@dataclass
class HTMLAnalysisResult:
    """Result of HTML metadata analysis."""
    is_html: bool = True
    content_type: Optional[str] = None
    truncated: bool = False
    response_size_bytes: int = 0
    generator: Optional[str] = None
    title: Optional[str] = None
    description_meta: Optional[str] = None
    technology_indicators: List[str] = field(default_factory=list)
    form_count: int = 0
    external_scripts: int = 0
    has_https_links: bool = False
    insecure_http_links: List[str] = field(default_factory=list)
    category: str = "HTML"


@dataclass
class HTTPInfo:
    """HTTP transaction metadata."""
    status_code: Optional[int] = None
    final_url: Optional[str] = None
    redirect_count: int = 0
    response_time_ms: Optional[float] = None
    content_type: Optional[str] = None


@dataclass
class ServerInfo:
    """Server and technology metadata."""
    server: Optional[str] = None
    x_powered_by: Optional[str] = None


@dataclass
class FindingItem:
    """Structured security finding for database storage / reporting."""
    check_name: str
    severity: str                       # "critical" | "high" | "medium" | "low" | "info"
    description: str
    remediation: str
    impact: Optional[str] = None
    category: str = "General"
    affected_url: Optional[str] = None
    evidence: Optional[str] = None
    confidence: str = "high"



@dataclass
class SecurityCheckItem:
    """Structured individual check outcome."""
    check_name: str
    category: str
    status: str                         # "passed" | "failed" | "warning" | "info"
    points: int
    description: str


@dataclass
class ScanEngineResult:
    """Top-level result returned by the scanner engine."""
    target_url: str
    scan_successful: bool
    score: float
    grade: str
    http: Optional[HTTPInfo] = None
    ssl: Optional[SSLResult] = None
    headers: Optional[HeaderAnalysisResult] = None
    cms: Optional[CMSResult] = None
    html: Optional[HTMLAnalysisResult] = None
    server: Optional[ServerInfo] = None
    security_checks: List[SecurityCheckItem] = field(default_factory=list)
    findings: List[FindingItem] = field(default_factory=list)
    error_type: Optional[str] = None
    error: Optional[str] = None
    duration_seconds: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert result to a plain JSON-compatible dictionary."""
        return asdict(self)
