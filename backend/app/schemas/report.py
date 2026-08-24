"""
VulnScan Lite — Report Pydantic Schemas
"""
from pydantic import BaseModel


class ReportPDFRequest(BaseModel):
    """Used internally when generating PDF reports."""
    scan_id: str
