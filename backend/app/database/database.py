"""
VulnScan Lite — SQLAlchemy Database Engine & Session Factory

Provides:
  - engine        : SQLAlchemy engine (psycopg3/psycopg[binary])
  - SessionLocal  : session factory
  - get_db        : FastAPI dependency for DB sessions
  - Base          : declarative base for all models

psycopg3 note: DATABASE_URL should use postgresql+psycopg:// scheme
or plain postgresql:// (auto-converted below).
"""
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from typing import Generator

from app.core.config import settings


def _build_engine_url(url: str) -> str:
    """
    Ensure the DATABASE_URL uses the correct psycopg3 dialect prefix.
    Converts:
      postgresql://...     → postgresql+psycopg://...
      postgres://...       → postgresql+psycopg://...
    Already correct format (postgresql+psycopg://) is returned unchanged.
    """
    if url.startswith("postgresql+psycopg://") or url.startswith("postgresql+psycopg2://"):
        return url
    if url.startswith("postgres://"):
        return "postgresql+psycopg://" + url[len("postgres://"):]
    if url.startswith("postgresql://"):
        return "postgresql+psycopg://" + url[len("postgresql://"):]
    return url

_db_url = _build_engine_url(settings.DATABASE_URL) if settings.DATABASE_URL else "sqlite:///./vulnscan.db"

if _db_url.startswith("sqlite"):
    engine = create_engine(
        _db_url,
        connect_args={"check_same_thread": False},
        echo=settings.ENVIRONMENT == "development",
    )
else:
    engine = create_engine(
        _db_url,
        pool_pre_ping=True,         # verify connections before use
        pool_size=10,
        max_overflow=20,
        echo=settings.ENVIRONMENT == "development",
    )

# Session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Declarative base shared by all models
Base = declarative_base()


def _extract_column_names(rows) -> set:
    """Extract column names from SQLite PRAGMA table_info rows robustly."""
    names = set()
    for r in rows:
        if isinstance(r, (tuple, list)) and len(r) > 1:
            names.add(r[1])
        elif hasattr(r, "name"):
            names.add(r.name)
        elif hasattr(r, "_mapping"):
            names.add(r._mapping.get("name") or r[1])
        else:
            try:
                names.add(r[1])
            except Exception:
                pass
    return names


def init_db() -> None:
    """Initialize database tables and apply lightweight migrations if needed."""
    Base.metadata.create_all(bind=engine)
    # If SQLite, ensure newer columns exist on existing tables
    if _db_url.startswith("sqlite"):
        try:
            with engine.connect() as conn:
                # Check users.name
                user_cols = _extract_column_names(conn.exec_driver_sql("PRAGMA table_info(users)").fetchall())
                if "name" not in user_cols and "email" in user_cols:
                    conn.exec_driver_sql("ALTER TABLE users ADD COLUMN name VARCHAR(255)")

                # Check scans columns
                scan_cols = _extract_column_names(conn.exec_driver_sql("PRAGMA table_info(scans)").fetchall())
                if "stage" not in scan_cols and "target_url" in scan_cols:
                    conn.exec_driver_sql("ALTER TABLE scans ADD COLUMN stage VARCHAR(50) DEFAULT 'queued'")
                if "authorization_type" not in scan_cols and "target_url" in scan_cols:
                    conn.exec_driver_sql("ALTER TABLE scans ADD COLUMN authorization_type VARCHAR(64) DEFAULT 'user_owned'")

                # Check findings columns
                finding_cols = _extract_column_names(conn.exec_driver_sql("PRAGMA table_info(findings)").fetchall())
                if "affected_url" not in finding_cols and "check_name" in finding_cols:
                    conn.exec_driver_sql("ALTER TABLE findings ADD COLUMN affected_url VARCHAR(2048)")
                if "evidence" not in finding_cols and "check_name" in finding_cols:
                    conn.exec_driver_sql("ALTER TABLE findings ADD COLUMN evidence TEXT")
                if "impact" not in finding_cols and "check_name" in finding_cols:
                    conn.exec_driver_sql("ALTER TABLE findings ADD COLUMN impact TEXT")
                if "confidence" not in finding_cols and "check_name" in finding_cols:
                    conn.exec_driver_sql("ALTER TABLE findings ADD COLUMN confidence VARCHAR(50) DEFAULT 'high'")

                conn.commit()
        except Exception as e:
            import logging
            logging.getLogger(__name__).warning("SQLite schema auto-sync notice: %s", e)
    else:
        try:
            with engine.connect() as conn:
                conn.exec_driver_sql("ALTER TABLE scans ADD COLUMN IF NOT EXISTS authorization_type VARCHAR(64) DEFAULT 'user_owned'")
                conn.exec_driver_sql("ALTER TABLE scans ADD COLUMN IF NOT EXISTS stage VARCHAR(50) DEFAULT 'queued'")
                conn.commit()
        except Exception as e:
            import logging
            logging.getLogger(__name__).warning("PostgreSQL schema auto-sync notice: %s", e)



def get_db() -> Generator[Session, None, None]:
    """
    FastAPI dependency that yields a database session and ensures
    it is closed after the request completes.
    """
    db: Session = SessionLocal()
    try:
        yield db
    finally:
        db.close()
