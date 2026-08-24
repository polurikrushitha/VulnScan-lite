"""
VulnScan Lite — Authentication API

Endpoints:
  POST /api/auth/register  — create a new user account
  POST /api/auth/login     — authenticate and receive a JWT
  GET  /api/auth/me        — get the authenticated user's profile

Rate-limited at the application level via slowapi.
"""
import logging
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.core.security import hash_password, verify_password, create_access_token, decode_access_token
from app.database.database import get_db
from app.database.models import User
from app.schemas.auth import UserRegisterRequest, UserLoginRequest, TokenResponse, UserResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/auth", tags=["Authentication"])


def get_current_user(
    request: Request,
    db: Session = Depends(get_db),
) -> User:
    """
    FastAPI dependency: extract and validate JWT from Authorization header,
    then return the corresponding User from the database.
    """
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid Authorization header.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = auth_header[len("Bearer "):]
    subject = decode_access_token(token)

    if not subject:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = db.query(User).filter(User.id == subject).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found.",
        )

    return user


@router.post("/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
def register(
    payload: UserRegisterRequest,
    db: Session = Depends(get_db),
) -> TokenResponse:
    """
    Register a new user account.

    - Email must be unique.
    - Password is hashed with bcrypt before storage.
    - Returns a JWT on success.
    """
    # Check for duplicate email
    existing = db.query(User).filter(User.email == payload.email).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email already exists.",
        )

    user = User(
        name=payload.name.strip() if payload.name else None,
        email=payload.email,
        password_hash=hash_password(payload.password),
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    token = create_access_token(subject=user.id)
    logger.info("New user registered: %s", user.email)
    return TokenResponse(
        access_token=token,
        user={"id": user.id, "name": user.name, "email": user.email},
    )


@router.post("/login", response_model=TokenResponse)
def login(
    payload: UserLoginRequest,
    db: Session = Depends(get_db),
) -> TokenResponse:
    """
    Authenticate a user and return a JWT.

    Deliberately returns the same error message for invalid email or password
    to prevent user enumeration.
    """
    user = db.query(User).filter(User.email == payload.email).first()

    if not user or not verify_password(payload.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
        )

    token = create_access_token(subject=user.id)
    logger.info("User logged in: %s", user.email)
    return TokenResponse(
        access_token=token,
        user={"id": user.id, "name": user.name, "email": user.email},
    )


@router.post("/logout")
def logout(
    current_user: User = Depends(get_current_user),
) -> dict:
    """
    Log out the authenticated user session.
    """
    logger.info("User logged out: %s", current_user.email)
    return {"status": "ok", "message": "Successfully logged out."}


@router.get("/me", response_model=UserResponse)
def me(
    current_user: User = Depends(get_current_user),
) -> UserResponse:
    """Return the authenticated user's profile."""
    return UserResponse(
        id=current_user.id,
        name=current_user.name,
        email=current_user.email,
        created_at=current_user.created_at.isoformat(),
    )
