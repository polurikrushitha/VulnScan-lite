"""
VulnScan Lite — Scan History API

Endpoints:
  GET /api/history — return all scans for the authenticated user
"""
import logging
from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.auth import get_current_user
from app.database.database import get_db
from app.database.models import Scan, User
from app.schemas.scan import ScanHistoryItem
from app.services.scoring import calculate_risk_level

logger = logging.getLogger("vulnscan.api.history")

router = APIRouter(prefix="/api/history", tags=["History"])


@router.get("", response_model=List[ScanHistoryItem])
def get_scan_history(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> List[ScanHistoryItem]:
    """
    Return all scans for the authenticated user, ordered by most recent first.
    Only returns the authenticated user's own scans.
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

