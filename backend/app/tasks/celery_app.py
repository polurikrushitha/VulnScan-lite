"""
VulnScan Lite — Celery Application Configuration

Configures Celery with Redis as broker and result backend.
REDIS_URL is loaded securely from application settings.
"""
from celery import Celery
from app.core.config import settings

# Fallback Redis URL for local development if not set in .env
broker_url = settings.REDIS_URL or "redis://localhost:6379/0"

celery_app = Celery(
    "vulnscan",
    broker=broker_url,
    backend=broker_url,
    include=["app.tasks.scan_tasks"],
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    # Execution timeouts
    task_soft_time_limit=120,   # 2 minutes soft limit
    task_time_limit=180,        # 3 minutes hard limit
    # Worker reliability
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    worker_prefetch_multiplier=1,
)
