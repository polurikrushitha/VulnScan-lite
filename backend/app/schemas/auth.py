"""
VulnScan Lite — Authentication Pydantic Schemas
"""
from typing import Optional
from pydantic import BaseModel, field_validator
import re

EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*\.[a-zA-Z]{2,}$")


class UserRegisterRequest(BaseModel):
    """Request body for POST /api/auth/register."""
    name: Optional[str] = None
    email: str
    password: str

    @field_validator("email")
    @classmethod
    def validate_email_syntax(cls, v: str) -> str:
        v = v.strip().lower()
        if not v or not EMAIL_REGEX.match(v):
            raise ValueError("Please enter a valid email address.")
        return v

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters long.")
        if not re.search(r"[A-Z]", v):
            raise ValueError("Password must contain at least one uppercase letter.")
        if not re.search(r"[0-9]", v):
            raise ValueError("Password must contain at least one digit.")
        return v


class UserLoginRequest(BaseModel):
    """Request body for POST /api/auth/login."""
    email: str
    password: str

    @field_validator("email")
    @classmethod
    def validate_email_syntax(cls, v: str) -> str:
        v = v.strip().lower()
        if not v or not EMAIL_REGEX.match(v):
            raise ValueError("Please enter a valid email address.")
        return v


class TokenResponse(BaseModel):
    """Response body after successful authentication."""
    access_token: str
    token_type: str = "bearer"
    user: Optional[dict] = None


class UserResponse(BaseModel):
    """Public user representation."""
    id: str
    name: Optional[str] = None
    email: str
    created_at: str

    model_config = {"from_attributes": True}

