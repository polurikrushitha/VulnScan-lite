"""
VulnScan Lite — Celery Scan Task

Asynchronous background worker task that:
  1. Opens an independent SQLAlchemy session.
  2. Updates the Scan record status from 'queued' to 'running' with 'started_at'.
  3. Executes the passive Scanner Engine.
  4. Persists the detailed results:
       - ScanResult (JSON data for SSL, headers, CMS, HTML)
       - SecurityCheck records (individual check points and statuses)
       - Finding records (actionable remediation items for failed checks)
  5. Updates Scan record with final score, letter grade, 'completed' status, and 'completed_at'.
  6. Safely handles errors without leaking internal stack traces.
"""
import dataclasses
import logging
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any

from celery import Task
from sqlalchemy.orm import Session

from app.tasks.celery_app import celery_app
from app.database.database import SessionLocal
from app.database.models import (
    Scan,
    ScanResult,
    SecurityCheck,
    Finding,
    ScanStatus,
    CheckStatus,
    FindingSeverity,
)
from app.services.remediation import get_remediation_text, get_remediation
from scanner.engine import run_scan
from scanner.models import ScanEngineResult

logger = logging.getLogger("vulnscan.tasks")


def _get_db() -> Session:
    """Create an isolated database session for the Celery worker thread."""
    return SessionLocal()


def _map_check_status(status_str: str) -> CheckStatus:
    """Convert string check status to CheckStatus enum."""
    status_lower = status_str.lower()
    if status_lower == "passed":
        return CheckStatus.PASSED
    elif status_lower == "failed":
        return CheckStatus.FAILED
    elif status_lower == "warning":
        return CheckStatus.WARNING
    else:
        return CheckStatus.INFO


def _map_finding_severity(severity_str: str) -> FindingSeverity:
    """Convert string severity to FindingSeverity enum."""
    sev_lower = severity_str.lower()
    if sev_lower == "critical":
        return FindingSeverity.CRITICAL
    elif sev_lower == "high":
        return FindingSeverity.HIGH
    elif sev_lower == "medium":
        return FindingSeverity.MEDIUM
    elif sev_lower == "low":
        return FindingSeverity.LOW
    else:
        return FindingSeverity.INFO


def run_scan_task(scan_id: str, target_url: str) -> dict:
    """
    Execute a passive security scan for a target URL and persist results.
    Can be executed by Celery workers or directly by FastAPI BackgroundTasks.
    """
    db: Session = _get_db()
    scan: Optional[Scan] = None

    logger.info("[ScanTask] Processing scan_id: %s, target_url: %s", scan_id, target_url)

    def update_stage(stage_name: str) -> None:
        try:
            s = db.query(Scan).filter(Scan.id == scan_id).first()
            if s:
                s.stage = stage_name
                db.commit()
        except Exception as e:
            logger.debug("[ScanTask] Could not update scan stage to %s: %s", stage_name, e)

    try:
        # 1. Fetch scan record and transition state to 'running'
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            logger.error("[ScanTask] Scan record %s not found in database.", scan_id)
            return {"scan_id": scan_id, "status": "failed", "error": "Scan record not found."}

        scan.status = ScanStatus.RUNNING
        scan.stage = "validating"
        scan.started_at = datetime.now(timezone.utc)
        db.commit()

        logger.info("[ScanTask] Status updated to 'running' for scan_id: %s", scan_id)
        logger.info("[ScanTask] Starting passive scanner engine for target: %s", target_url)

        # 2. Run the passive scanner engine with stage callback
        result: ScanEngineResult = run_scan(target_url, stage_callback=update_stage)

        logger.info("[ScanTask] Scanner finished for target: %s (success=%s)", target_url, result.scan_successful)

        # 3. Persist the results
        _persist_results(db, scan, result)

        logger.info(
            "[ScanTask] Status updated to '%s' for scan_id: %s (Score: %s, Grade: %s)",
            scan.status.value,
            scan_id,
            scan.score,
            scan.grade,
        )
        return {"scan_id": scan_id, "status": scan.status.value}

    except Exception as exc:
        logger.exception("[ScanTask] Failed for scan_id %s: %s", scan_id, exc)
        if scan:
            try:
                scan.status = ScanStatus.FAILED
                scan.stage = "failed"
                scan.error_message = "An unexpected error occurred during scan execution."
                scan.completed_at = datetime.now(timezone.utc)
                db.commit()
            except Exception as db_err:
                logger.error("[ScanTask] Failed to update scan failure status in DB: %s", db_err)
                db.rollback()

        return {"scan_id": scan_id, "status": "failed", "error": str(exc)}

    finally:
        db.close()


@celery_app.task(bind=True, name="scan_tasks.execute_scan", max_retries=1)
def execute_scan(self: Task, scan_id: str, target_url: str) -> dict:
    """
    Celery task wrapper around run_scan_task.
    """
    logger.info("[Celery] Task received — scan_id: %s, target_url: %s", scan_id, target_url)
    try:
        return run_scan_task(scan_id=scan_id, target_url=target_url)
    except Exception as exc:
        logger.exception("[Celery] Unhandled task exception for scan_id %s: %s", scan_id, exc)
        if hasattr(self, "request") and getattr(self.request, "retries", 0) < getattr(self, "max_retries", 1):
            raise self.retry(exc=exc, countdown=5)
        return {"scan_id": scan_id, "status": "failed", "error": str(exc)}


def _persist_results(db: Session, scan: Scan, result: ScanEngineResult) -> None:
    """
    Persist scanner engine results and update the Scan record transactionally.

    Args:
        db:     Active database session.
        scan:   The Scan ORM instance.
        result: The ScanEngineResult from the engine.
    """
    now = datetime.now(timezone.utc)

    if not result.scan_successful:
        scan.status = ScanStatus.FAILED
        scan.stage = "failed"
        scan.error_message = result.error or "Scan failed."
        scan.completed_at = now
        db.commit()
        return

    # 1. ScanResult (Raw structured JSON diagnostic data)
    ssl_dict = dataclasses.asdict(result.ssl) if result.ssl else None
    header_dict = dataclasses.asdict(result.headers) if result.headers else None
    cms_dict = dataclasses.asdict(result.cms) if result.cms else None
    html_dict = dataclasses.asdict(result.html) if result.html else None

    scan_result = ScanResult(
        scan_id=scan.id,
        ssl_data=ssl_dict,
        header_data=header_dict,
        cms_data=cms_dict,
        html_data=html_dict,
    )
    db.add(scan_result)

    # 2. SecurityChecks (Structured individual checks)
    checks_to_save: List[SecurityCheck] = []
    if result.security_checks:
        for chk in result.security_checks:
            checks_to_save.append(SecurityCheck(
                scan_id=scan.id,
                check_name=chk.check_name,
                category=chk.category,
                status=_map_check_status(chk.status),
                points=chk.points,
                description=chk.description,
            ))
    elif result.headers:
        # Fallback to headers if security_checks not pre-populated
        for check in result.headers.checks:
            checks_to_save.append(SecurityCheck(
                scan_id=scan.id,
                check_name=check.header_name,
                category=check.category,
                status=CheckStatus.PASSED if check.present else CheckStatus.FAILED,
                points=check.points,
                description=check.description,
            ))

    if checks_to_save:
        db.add_all(checks_to_save)

    # 3. Findings (Actionable failed/warning items with remediation guidance)
    findings_to_save: List[Finding] = []
    if result.findings:
        for f in result.findings:
            findings_to_save.append(Finding(
                scan_id=scan.id,
                check_name=f.check_name,
                severity=_map_finding_severity(f.severity),
                description=f.description,
                remediation=f.remediation,
                impact=f.impact,
                affected_url=f.affected_url or scan.target_url,
                evidence=f.evidence,
                confidence=f.confidence or "high",
            ))
    else:
        # Fallback generation for header defects
        if result.headers:
            for check in result.headers.checks:
                if not check.present and check.points < 0:
                    findings_to_save.append(Finding(
                        scan_id=scan.id,
                        check_name=f"Missing {check.header_name}",
                        severity=FindingSeverity.HIGH if check.points <= -10 else FindingSeverity.MEDIUM,
                        description=check.description,
                        remediation=get_remediation_text(check.header_name),
                        impact=check.description,
                        affected_url=scan.target_url,
                        evidence=f"Header '{check.header_name}' missing from response.",
                        confidence="high",
                    ))

    if findings_to_save:
        db.add_all(findings_to_save)

    # 4. Update the Scan parent record
    scan.status = ScanStatus.COMPLETED
    scan.stage = "completed"
    scan.score = result.score
    scan.grade = result.grade
    scan.completed_at = now
    scan.error_message = None

    db.commit()
