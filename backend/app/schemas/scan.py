"""
VulnScan Lite — Scan Pydantic Schemas

Defines request and response schemas for scan operations, status polling,
authorization basis verification, structured consent enforcement, and reporting.
"""
from enum import Enum
from typing import Optional, List, Any, Dict
from pydantic import BaseModel, field_validator


class AuthorizationTypeEnum(str, Enum):
    USER_OWNED = "user_owned"
    ORGANIZATION_APPROVED = "organization_approved"
    EXPLICIT_PERMISSION = "explicit_permission"


CURRENT_CONSENT_VERSION = "Authorized Scanning Policy v1.0"


class ScanCreateRequest(BaseModel):
    """
    Request payload for POST /api/scan with mandatory authorization & consent.
    """
    url: str
    authorization_type: AuthorizationTypeEnum
    target_confirmed: bool = False
    consent_version: str = CURRENT_CONSENT_VERSION
    confirmed_ownership: bool = False
    confirmed_requests_acknowledged: bool = False
    confirmed_authorized_testing_only: bool = False
    confirmed_passive_analysis_understood: bool = False
    confirmed_responsibility_accepted: bool = False

    @field_validator("url")
    @classmethod
    def validate_url_syntax(cls, v: str) -> str:
        if not v or not isinstance(v, str):
            raise ValueError("URL cannot be empty.")
        v = v.strip()
        if not v.startswith(("http://", "https://")):
            raise ValueError("URL must start with http:// or https://")
        return v

    @field_validator("target_confirmed")
    @classmethod
    def validate_target_confirmation(cls, v: bool) -> bool:
        if not v:
            raise ValueError("Explicit target confirmation is required before scanning.")
        return v

    @field_validator("consent_version")
    @classmethod
    def validate_consent_version(cls, v: str) -> str:
        if v != CURRENT_CONSENT_VERSION:
            raise ValueError(
                f"Invalid or outdated consent version '{v}'. Current version is '{CURRENT_CONSENT_VERSION}'."
            )
        return v

    @field_validator(
        "confirmed_ownership",
        "confirmed_requests_acknowledged",
        "confirmed_authorized_testing_only",
        "confirmed_passive_analysis_understood",
        "confirmed_responsibility_accepted",
    )
    @classmethod
    def validate_all_consent_checkboxes(cls, v: bool, info) -> bool:
        if not v:
            field_name = info.field_name
            raise ValueError(f"Mandatory consent stipulation '{field_name}' must be explicitly confirmed.")
        return v


class ScanCreateResponse(BaseModel):
    """Response returned immediately after queuing a scan."""
    scan_id: str
    status: str = "queued"
    stage: str = "queued"
    authorization_type: Optional[str] = None


class ScanStatusResponse(BaseModel):
    """Lightweight response for status polling (GET /api/scan/{scan_id}/status)."""
    scan_id: str
    status: str                         # "queued" | "running" | "completed" | "failed"
    stage: Optional[str] = "queued"     # "queued" | "auth_verified" | "validating" | "policy_check" | "connecting" | "scanning" | "analyzing" | "generating_report" | "completed" | "failed"
    message: Optional[str] = None       # human-readable stage message
    score: Optional[float] = None
    grade: Optional[str] = None
    risk_level: Optional[str] = None
    authorization_type: Optional[str] = None
    error: Optional[str] = None


class SecurityCheckSchema(BaseModel):
    """Individual security check item."""
    id: str
    check_name: str
    category: str
    status: str                         # "passed" | "failed" | "warning" | "info"
    points: int
    description: Optional[str] = None

    model_config = {"from_attributes": True}


class FindingSchema(BaseModel):
    """Individual security finding item."""
    id: str
    check_name: str
    severity: str                       # "critical" | "high" | "medium" | "low" | "info"
    description: str
    remediation: Optional[str] = None
    impact: Optional[str] = None
    affected_url: Optional[str] = None
    evidence: Optional[str] = None
    confidence: Optional[str] = "high"

    model_config = {"from_attributes": True}


class ConsentAuditSchema(BaseModel):
    """Minimal public audit information for verified scan consent."""
    consent_version: str
    authorization_state: str
    scan_status: str
    confirmed_at: Optional[str] = None

    model_config = {"from_attributes": True}


class ScanResultResponse(BaseModel):
    """Detailed result payload for GET /api/scan/{scan_id}/result."""
    scan_id: str
    target_url: str
    status: str
    stage: Optional[str] = None
    authorization_type: Optional[str] = None
    consent_audit: Optional[ConsentAuditSchema] = None
    score: Optional[float] = None
    grade: Optional[str] = None
    risk_level: Optional[str] = None
    duration_seconds: Optional[float] = None
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    created_at: str
    ssl_data: Optional[Dict[str, Any]] = None
    header_data: Optional[Dict[str, Any]] = None
    cms_data: Optional[Dict[str, Any]] = None
    html_data: Optional[Dict[str, Any]] = None
    security_checks: List[SecurityCheckSchema] = []
    findings: List[FindingSchema] = []
    error: Optional[str] = None

    model_config = {"from_attributes": True}


class ScanHistoryItem(BaseModel):
    """Summary item for historical scan list."""
    scan_id: str
    target_url: str
    status: str
    stage: Optional[str] = None
    authorization_type: Optional[str] = None
    score: Optional[float] = None
    grade: Optional[str] = None
    risk_level: Optional[str] = None
    findings_count: int = 0
    created_at: str
    completed_at: Optional[str] = None

    model_config = {"from_attributes": True}

