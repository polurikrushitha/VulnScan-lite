"""
VulnScan Lite — SQLAlchemy ORM Models

Tables:
  - users
  - scans
  - scan_results
  - security_checks
  - findings
"""
import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Column,
    String,
    Integer,
    Float,
    DateTime,
    ForeignKey,
    Text,
    Enum as SAEnum,
    JSON,
    Boolean,
)
from sqlalchemy.types import TypeDecorator
from sqlalchemy.dialects.postgresql import UUID as PG_UUID, JSONB as PG_JSONB
from sqlalchemy.orm import relationship
import enum

from app.database.database import Base

GUID = String(36).with_variant(PG_UUID(as_uuid=False), "postgresql")
JSON_TYPE = JSON().with_variant(PG_JSONB, "postgresql")


class RobustEnum(TypeDecorator):
    """
    Resilient Enum TypeDecorator that seamlessly maps both string values
    (e.g., 'queued', 'user_owned') and enum member names (e.g., 'QUEUED', 'USER_OWNED')
    to and from Python enum.Enum instances across SQLite and PostgreSQL.
    """
    impl = String(64)
    cache_ok = True

    def __init__(self, enum_cls, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.enum_cls = enum_cls

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        if isinstance(value, self.enum_cls):
            return value.value
        val_str = str(value).lower().strip()
        for member in self.enum_cls:
            if member.value.lower() == val_str or member.name.lower() == val_str:
                return member.value
        return str(value)

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        if isinstance(value, self.enum_cls):
            return value
        val_str = str(value).strip()
        for member in self.enum_cls:
            if member.value == val_str:
                return member
        val_lower = val_str.lower()
        for member in self.enum_cls:
            if member.value.lower() == val_lower or member.name.lower() == val_lower:
                return member
        try:
            return self.enum_cls(value)
        except Exception:
            return list(self.enum_cls)[0]


def _uuid() -> str:
    """Generate a new UUID4 string."""
    return str(uuid.uuid4())


def _now() -> datetime:
    """Return current UTC datetime."""
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class AuthorizationType(str, enum.Enum):
    USER_OWNED = "user_owned"
    ORGANIZATION_APPROVED = "organization_approved"
    EXPLICIT_PERMISSION = "explicit_permission"


class ScanStatus(str, enum.Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class CheckStatus(str, enum.Enum):
    PASSED = "passed"
    FAILED = "failed"
    WARNING = "warning"
    INFO = "info"


class FindingSeverity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# ---------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------

class User(Base):
    __tablename__ = "users"

    id = Column(GUID, primary_key=True, default=_uuid)
    name = Column(String(255), nullable=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    created_at = Column(DateTime(timezone=True), default=_now, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=_now, onupdate=_now, nullable=False)

    # Relationships
    scans = relationship("Scan", back_populates="user", cascade="all, delete-orphan")
    consent_audits = relationship("ConsentAudit", back_populates="user", cascade="all, delete-orphan")

    def __repr__(self) -> str:
        return f"<User id={self.id} email={self.email}>"


# ---------------------------------------------------------------------------
# Scans
# ---------------------------------------------------------------------------

class Scan(Base):
    __tablename__ = "scans"

    id = Column(GUID, primary_key=True, default=_uuid)
    user_id = Column(GUID, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    target_url = Column(String(2048), nullable=False)
    authorization_type = Column(RobustEnum(AuthorizationType), default=AuthorizationType.USER_OWNED, nullable=False)
    status = Column(RobustEnum(ScanStatus), default=ScanStatus.QUEUED, nullable=False)
    stage = Column(String(50), default="queued", nullable=True)
    score = Column(Float, nullable=True)
    grade = Column(String(10), nullable=True)
    error_message = Column(Text, nullable=True)
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=_now, nullable=False)

    # Relationships
    user = relationship("User", back_populates="scans")
    result = relationship("ScanResult", back_populates="scan", uselist=False, cascade="all, delete-orphan")
    security_checks = relationship("SecurityCheck", back_populates="scan", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
    consent_audit = relationship("ConsentAudit", back_populates="scan", uselist=False, cascade="all, delete-orphan")

    def __repr__(self) -> str:
        return f"<Scan id={self.id} url={self.target_url} status={self.status} auth={self.authorization_type}>"


# ---------------------------------------------------------------------------
# Scan Results (detailed JSON data per scan)
# ---------------------------------------------------------------------------

class ScanResult(Base):
    __tablename__ = "scan_results"

    id = Column(GUID, primary_key=True, default=_uuid)
    scan_id = Column(GUID, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, unique=True, index=True)
    ssl_data = Column(JSON_TYPE, nullable=True)
    header_data = Column(JSON_TYPE, nullable=True)
    cms_data = Column(JSON_TYPE, nullable=True)
    html_data = Column(JSON_TYPE, nullable=True)
    created_at = Column(DateTime(timezone=True), default=_now, nullable=False)

    # Relationships
    scan = relationship("Scan", back_populates="result")

    def __repr__(self) -> str:
        return f"<ScanResult id={self.id} scan_id={self.scan_id}>"


# ---------------------------------------------------------------------------
# Security Checks
# ---------------------------------------------------------------------------

class SecurityCheck(Base):
    __tablename__ = "security_checks"

    id = Column(GUID, primary_key=True, default=_uuid)
    scan_id = Column(GUID, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    check_name = Column(String(255), nullable=False)
    category = Column(String(100), nullable=False)
    status = Column(RobustEnum(CheckStatus), nullable=False)
    points = Column(Integer, default=0, nullable=False)
    description = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=_now, nullable=False)

    # Relationships
    scan = relationship("Scan", back_populates="security_checks")

    def __repr__(self) -> str:
        return f"<SecurityCheck id={self.id} name={self.check_name} status={self.status}>"


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

class Finding(Base):
    __tablename__ = "findings"

    id = Column(GUID, primary_key=True, default=_uuid)
    scan_id = Column(GUID, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    check_name = Column(String(255), nullable=False)
    severity = Column(RobustEnum(FindingSeverity), nullable=False)
    description = Column(Text, nullable=False)
    remediation = Column(Text, nullable=True)
    impact = Column(Text, nullable=True)
    affected_url = Column(String(2048), nullable=True)
    evidence = Column(Text, nullable=True)
    confidence = Column(String(50), default="high", nullable=True)
    created_at = Column(DateTime(timezone=True), default=_now, nullable=False)

    # Relationships
    scan = relationship("Scan", back_populates="findings")

    def __repr__(self) -> str:
        return f"<Finding id={self.id} check={self.check_name} severity={self.severity}>"


# ---------------------------------------------------------------------------
# Consent Audit Log
# ---------------------------------------------------------------------------

class ConsentAudit(Base):
    __tablename__ = "consent_audits"

    id = Column(GUID, primary_key=True, default=_uuid)
    user_id = Column(GUID, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    scan_id = Column(GUID, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, unique=True, index=True)
    target_url = Column(String(2048), nullable=False)
    consent_version = Column(String(50), default="Authorized Scanning Policy v1.0", nullable=False)
    authorization_state = Column(String(50), nullable=False)
    scan_status = Column(String(50), default="queued", nullable=False)
    confirmed_ownership = Column(Boolean, default=True, nullable=False)
    confirmed_requests_acknowledged = Column(Boolean, default=True, nullable=False)
    confirmed_authorized_testing_only = Column(Boolean, default=True, nullable=False)
    confirmed_passive_analysis_understood = Column(Boolean, default=True, nullable=False)
    confirmed_responsibility_accepted = Column(Boolean, default=True, nullable=False)
    client_ip = Column(String(100), nullable=True)
    created_at = Column(DateTime(timezone=True), default=_now, nullable=False)

    # Relationships
    user = relationship("User", back_populates="consent_audits")
    scan = relationship("Scan", back_populates="consent_audit")

    def __repr__(self) -> str:
        return f"<ConsentAudit id={self.id} user_id={self.user_id} scan_id={self.scan_id} auth={self.authorization_state}>"

