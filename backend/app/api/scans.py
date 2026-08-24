"""
VulnScan Lite — Scan API

Endpoints:
  POST /api/scan                    — Validate authorization, log consent, and enqueue a new scan (JWT required)
  GET  /api/scan/{scan_id}/status  — Lightweight status lookup for polling (Owner only)
  GET  /api/scan/{scan_id}/result  — Full relational scan result with consent audit (Owner only)
  GET  /api/scan/{scan_id}/report  — Alias for full scan result (Owner only)
"""
import logging
from typing import List, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.api.auth import get_current_user
from app.core.config import settings
from app.database.database import get_db
from app.database.models import Scan, ScanResult, ScanStatus, User, AuthorizationType, ConsentAudit
from app.schemas.scan import (
    ScanCreateRequest,
    ScanCreateResponse,
    ScanStatusResponse,
    ScanResultResponse,
    SecurityCheckSchema,
    FindingSchema,
    ConsentAuditSchema,
    ScanHistoryItem,
)
from app.tasks.scan_tasks import execute_scan, run_scan_task
from app.services.scoring import calculate_risk_level
from scanner.engine import validate_url, URLValidationError

logger = logging.getLogger("vulnscan.api.scans")

router = APIRouter(prefix="/api/scan", tags=["Scans"])

MAX_CONCURRENT_SCANS_PER_USER = 3


def _get_scan_or_404(scan_id: str, db: Session) -> Scan:
    """Retrieve a scan by UUID or raise HTTP 404."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan '{scan_id}' not found.",
        )
    return scan


def _assert_owner(scan: Scan, current_user: User) -> None:
    """Enforce that the requesting user owns the scan."""
    if scan.user_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not have permission to access this scan.",
        )


STAGE_MESSAGES = {
    "queued": "Scan queued in worker pool...",
    "preparing": "Preparing authorized scan environment...",
    "auth_verified": "Scan authorization verified & consent logged...",
    "validating": "Validating target URL syntax...",
    "policy_check": "Enforcing SSRF security policies & DNS verification...",
    "connecting": "Checking target reachability & connectivity...",
    "scanning": "Inspecting SSL/TLS certificates and HTTP transport...",
    "analyzing": "Analyzing security headers, HTML metadata & CMS signatures...",
    "generating_report": "Calculating score and compiling security report...",
    "completed": "Scan completed successfully.",
    "failed": "Scan failed.",
}


@router.get("", response_model=List[ScanHistoryItem])
def get_authorized_scans(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> List[ScanHistoryItem]:
    """
    Retrieve all scans for the authenticated user, ordered by most recent first.
    Enforces user identity exclusively from the server-side JWT session.
    """
    try:
        scans = (
            db.query(Scan)
            .filter(Scan.user_id == current_user.id)
            .order_by(Scan.created_at.desc())
            .all()
        )

        return [
            ScanHistoryItem(
                scan_id=str(s.id),
                target_url=s.target_url,
                status=s.status.value if hasattr(s.status, "value") else str(s.status),
                stage=s.stage,
                authorization_type=(
                    s.authorization_type.value
                    if hasattr(s.authorization_type, "value") and s.authorization_type
                    else (str(s.authorization_type) if s.authorization_type else "user_owned")
                ),
                score=s.score,
                grade=s.grade,
                risk_level=calculate_risk_level(s.score),
                findings_count=len(s.findings) if s.findings else 0,
                created_at=s.created_at.isoformat() if s.created_at else "",
                completed_at=s.completed_at.isoformat() if s.completed_at else None,
            )
            for s in scans
        ]
    except Exception as e:
        logger.error(
            "Safe Error: Failed to retrieve user scan history (user_id=%s, error_type=%s)",
            current_user.id,
            type(e).__name__,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while retrieving scan history.",
        )


@router.post("", response_model=ScanCreateResponse, status_code=status.HTTP_202_ACCEPTED)
def create_scan(
    request: Request,
    payload: ScanCreateRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ScanCreateResponse:
    """
    Initiate an authorized web security scan.

    Workflow:
      1. Authentication Gate: Enforces valid user session.
      2. Authorization & Consent Verification: Validates ownership/authorization basis
         and complete 5-point explicit consent checklist.
      3. Concurrency Guard: Enforces limits on simultaneous scans.
      4. Target Validation & SSRF Enforcement: Validates URL and checks SSRF policy.
         Consent NEVER bypasses SSRF controls.
      5. Persistent Audit: Atomically logs ConsentAudit record.
      6. Scan Dispatch: Queues scan in worker pool.
    """
    # 1. Concurrency limit check
    active_scans_count = (
        db.query(Scan)
        .filter(
            Scan.user_id == current_user.id,
            Scan.status.in_([ScanStatus.QUEUED, ScanStatus.RUNNING]),
        )
        .count()
    )
    if active_scans_count >= MAX_CONCURRENT_SCANS_PER_USER:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Active scan limit reached. Please wait for ongoing scans to complete before initiating a new one.",
        )

    # 2. Validate URL & apply SSRF protection
    try:
        validated_url = validate_url(payload.url)
    except URLValidationError as e:
        logger.warning(
            "[SECURITY_EVENT] Target rejected by policy: user=%s, url=%s, reason=%s",
            current_user.id,
            payload.url,
            e,
        )
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Target rejected by VulnScan Lite security policy.",
        )

    # Map authorization type
    auth_type_val = payload.authorization_type.value
    auth_enum = AuthorizationType(auth_type_val)

    # 3. Create Scan record
    scan = Scan(
        user_id=current_user.id,
        target_url=validated_url,
        authorization_type=auth_enum,
        status=ScanStatus.QUEUED,
        stage="auth_verified",
    )
    db.add(scan)
    db.flush()

    # 4. Create ConsentAudit record (Minimal persistent audit trail)
    client_host = request.client.host if request.client else None
    audit_record = ConsentAudit(
        user_id=current_user.id,
        scan_id=scan.id,
        target_url=validated_url,
        consent_version=payload.consent_version,
        authorization_state=auth_type_val,
        scan_status=ScanStatus.QUEUED.value,
        confirmed_ownership=payload.confirmed_ownership,
        confirmed_requests_acknowledged=payload.confirmed_requests_acknowledged,
        confirmed_authorized_testing_only=payload.confirmed_authorized_testing_only,
        confirmed_passive_analysis_understood=payload.confirmed_passive_analysis_understood,
        confirmed_responsibility_accepted=payload.confirmed_responsibility_accepted,
        client_ip=client_host,
    )
    db.add(audit_record)
    db.commit()
    db.refresh(scan)

    # 5. Security Event Logging
    logger.info(
        "[SECURITY_EVENT] Consent accepted: user=%s, version=%s",
        current_user.id,
        payload.consent_version,
    )
    logger.info(
        "[SECURITY_EVENT] Scan authorization verified: user=%s, target=%s, auth_type=%s",
        current_user.id,
        validated_url,
        auth_type_val,
    )
    logger.info(
        "[SECURITY_EVENT] Scan started: scan_id=%s, target=%s",
        scan.id,
        validated_url,
    )

    # 6. Enqueue asynchronous task
    try:
        execute_scan.delay(str(scan.id), validated_url)
    except Exception as exc:
        logger.warning(
            "Celery dispatch failed. Executing scan %s via background task fallback: %s",
            scan.id,
            exc,
        )
        background_tasks.add_task(run_scan_task, str(scan.id), validated_url)

    return ScanCreateResponse(
        scan_id=str(scan.id),
        status="queued",
        stage="auth_verified",
        authorization_type=auth_type_val,
    )


@router.get("/{scan_id}/status", response_model=ScanStatusResponse)
def get_scan_status(
    scan_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ScanStatusResponse:
    """
    Poll the current status and stage of a scan.

    - Fast, lightweight database read.
    - Enforces ownership: only the user who created the scan can poll status.
    """
    scan = _get_scan_or_404(scan_id, db)
    _assert_owner(scan, current_user)

    current_stage = scan.stage or scan.status.value
    msg = STAGE_MESSAGES.get(current_stage, STAGE_MESSAGES.get(scan.status.value, "Processing scan..."))
    auth_type_str = scan.authorization_type.value if hasattr(scan.authorization_type, "value") else str(scan.authorization_type)

    return ScanStatusResponse(
        scan_id=str(scan.id),
        status=scan.status.value,
        stage=current_stage,
        message=msg,
        score=scan.score,
        grade=scan.grade,
        risk_level=calculate_risk_level(scan.score),
        authorization_type=auth_type_str,
        error=scan.error_message,
    )


@router.get("/{scan_id}/result", response_model=ScanResultResponse)
def get_scan_result(
    scan_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ScanResultResponse:
    """
    Retrieve the full relational findings, diagnostic report, and consent audit for a completed scan.

    - Enforces ownership: only the user who created the scan can retrieve results.
    - Returns HTTP 400 if the scan is still queued or running.
    """
    scan = _get_scan_or_404(scan_id, db)
    _assert_owner(scan, current_user)

    if scan.status not in (ScanStatus.COMPLETED, ScanStatus.FAILED):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Scan is not yet complete. Current status: {scan.status.value}.",
        )

    # Fetch stored relational data
    result = db.query(ScanResult).filter(ScanResult.scan_id == scan_id).first()
    consent_audit = db.query(ConsentAudit).filter(ConsentAudit.scan_id == scan_id).first()

    consent_audit_data = None
    if consent_audit:
        consent_audit_data = ConsentAuditSchema(
            consent_version=consent_audit.consent_version,
            authorization_state=consent_audit.authorization_state,
            scan_status=consent_audit.scan_status,
            confirmed_at=consent_audit.created_at.isoformat() if consent_audit.created_at else None,
        )

    checks = [
        SecurityCheckSchema(
            id=str(c.id),
            check_name=c.check_name,
            category=c.category,
            status=c.status.value,
            points=c.points,
            description=c.description,
        )
        for c in scan.security_checks
    ]

    findings = [
        FindingSchema(
            id=str(f.id),
            check_name=f.check_name,
            severity=f.severity.value,
            description=f.description,
            remediation=f.remediation,
            impact=f.impact,
            affected_url=f.affected_url or scan.target_url,
            evidence=f.evidence,
            confidence=f.confidence or "high",
        )
        for f in scan.findings
    ]

    duration: Optional[float] = None
    if scan.started_at and scan.completed_at:
        duration = round((scan.completed_at - scan.started_at).total_seconds(), 2)

    auth_type_str = scan.authorization_type.value if hasattr(scan.authorization_type, "value") else str(scan.authorization_type)

    return ScanResultResponse(
        scan_id=str(scan.id),
        target_url=scan.target_url,
        status=scan.status.value,
        stage=scan.stage,
        authorization_type=auth_type_str,
        consent_audit=consent_audit_data,
        score=scan.score,
        grade=scan.grade,
        risk_level=calculate_risk_level(scan.score),
        duration_seconds=duration,
        started_at=scan.started_at.isoformat() if scan.started_at else None,
        completed_at=scan.completed_at.isoformat() if scan.completed_at else None,
        created_at=scan.created_at.isoformat(),
        ssl_data=result.ssl_data if result else None,
        header_data=result.header_data if result else None,
        cms_data=result.cms_data if result else None,
        html_data=result.html_data if result else None,
        security_checks=checks,
        findings=findings,
        error=scan.error_message,
    )


@router.get("/{scan_id}/report", response_model=ScanResultResponse)
def get_scan_report(
    scan_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ScanResultResponse:
    """Alias for /api/scan/{scan_id}/result to retrieve the diagnostic report."""
    return get_scan_result(scan_id=scan_id, db=db, current_user=current_user)

