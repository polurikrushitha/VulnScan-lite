"""
VulnScan Lite — FastAPI Application Entry Point

Registers:
  - CORS middleware
  - Rate limiting (slowapi)
  - API routers: auth, scans, history, reports
  - Health check endpoint

DISCLAIMER: Only scan websites you own or have explicit permission to test.
VulnScan Lite performs passive security analysis only.
"""
import logging
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI, Request, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.config import settings
from app.database.database import get_db
from app.api import auth, scans, history, reports

# ---------------------------------------------------------------------------
# Logging configuration
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Rate limiter
# ---------------------------------------------------------------------------
limiter = Limiter(key_func=get_remote_address, default_limits=["200/minute"])

# ---------------------------------------------------------------------------
# App lifecycle
# ---------------------------------------------------------------------------

from app.database.database import Base, engine, get_db, init_db

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Startup and shutdown logic."""
    logger.info("VulnScan Lite starting up. Environment: %s", settings.ENVIRONMENT)
    init_db()
    yield
    logger.info("VulnScan Lite shutting down.")


# ---------------------------------------------------------------------------
# FastAPI Application
# ---------------------------------------------------------------------------
app = FastAPI(
    title="VulnScan Lite API",
    description=(
        "On-Demand Web Security Health Scanner. "
        "DISCLAIMER: Only scan websites you own or have explicit permission to test. "
        "VulnScan Lite performs passive security analysis only."
    ),
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    lifespan=lifespan,
)

# ---------------------------------------------------------------------------
# Middleware
# ---------------------------------------------------------------------------
_cors_origins = settings.get_cors_origins()
_allow_origin_regex = None
if "*" in _cors_origins:
    _allow_origin_regex = r".*"
    _cors_origins = []
else:
    _allow_origin_regex = r"https://.*\.vercel\.app|https://.*\.onrender\.com|http://localhost.*|http://127\.0\.0\.1.*"

app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_origin_regex=_allow_origin_regex,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Rate limiting
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ---------------------------------------------------------------------------
# Routers
# ---------------------------------------------------------------------------
app.include_router(auth.router)
app.include_router(scans.router)
app.include_router(history.router)
app.include_router(reports.router)
# ---------------------------------------------------------------------------
# Health Checks & Docs Redirect
# ---------------------------------------------------------------------------

@app.get("/", tags=["Health"])
@limiter.exempt
async def root() -> dict:
    """Root endpoint welcoming users and pointing to API documentation."""
    return {
        "status": "ok",
        "service": "VulnScan Lite API",
        "version": "1.0.0",
        "docs": "/api/docs",
        "health": "/health",
    }


@app.get("/docs", include_in_schema=False)
async def docs_redirect() -> RedirectResponse:
    """Redirect /docs to /api/docs."""
    return RedirectResponse(url="/api/docs")


@app.get("/health", tags=["Health"])
@limiter.exempt
async def health_check() -> dict:
    """
    Health check endpoint.
    Returns {"status": "ok"} when the API is running.
    """
    return {"status": "ok", "service": "VulnScan Lite API", "version": "1.0.0"}


@app.get("/health/db", tags=["Health"])
@limiter.exempt
def db_health_check(db: Session = Depends(get_db)) -> dict:
    """
    Database health check endpoint.
    Verifies database connectivity via SELECT 1 without exposing credentials or internal strings.
    """
    try:
        db.execute(text("SELECT 1"))
        return {"status": "ok", "database": "connected"}
    except Exception as e:
        logger.error("Database health check failed: %s", type(e).__name__)
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"status": "error", "database": "disconnected", "detail": "Database unavailable."},
        )


# ---------------------------------------------------------------------------
# Global error handler (prevent stack trace leakage)
# ---------------------------------------------------------------------------

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    logger.exception("Unhandled exception for %s %s: %s", request.method, request.url, exc)
    return JSONResponse(
        status_code=500,
        content={"detail": "An internal server error occurred. Please try again later."},
    )
