"""Authentication routes for admin login and initial setup."""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select

from auth import verify_password, create_access_token, decode_token, hash_password, is_setup_required
from config import settings
from db import async_session
from models import AdminUser

router = APIRouter()


# --- Schemas ---

class LoginRequest(BaseModel):
    email: str
    password: str


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    email: str


class TokenVerifyResponse(BaseModel):
    valid: bool
    email: str | None = None


class SetupRequest(BaseModel):
    email: str = Field(..., description="Admin email address")
    password: str = Field(..., min_length=8, description="Password (min 8 chars)")
    password_confirm: str = Field(..., description="Confirm password")


class SetupStatusResponse(BaseModel):
    setup_required: bool
    message: str


# --- Endpoints ---

@router.get("/setup-status", response_model=SetupStatusResponse)
async def check_setup_status():
    """Check if initial setup is needed (no admin exists yet)."""
    needs_setup = await is_setup_required()
    return SetupStatusResponse(
        setup_required=needs_setup,
        message="Initial setup required. Create your admin account." if needs_setup
        else "System configured. Please login.",
    )


@router.post("/setup", response_model=LoginResponse)
async def initial_setup(req: SetupRequest):
    """
    First-time setup: create the admin account.
    Only works when no admin exists yet.
    """
    needs_setup = await is_setup_required()
    if not needs_setup:
        raise HTTPException(
            status_code=403,
            detail="Setup already completed. Use /login instead.",
        )

    if req.password != req.password_confirm:
        raise HTTPException(status_code=400, detail="Passwords do not match.")

    if len(req.password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters.")

    async with async_session() as session:
        admin = AdminUser(
            email=req.email,
            password_hash=hash_password(req.password),
            is_active=True,
        )
        session.add(admin)
        await session.commit()

    # Auto-login after setup
    token = create_access_token({"sub": req.email})
    return LoginResponse(access_token=token, email=req.email)


@router.post("/login", response_model=LoginResponse)
async def admin_login(req: LoginRequest):
    """Admin login — returns JWT token."""
    # Check if setup is needed first
    needs_setup = await is_setup_required()
    if needs_setup:
        raise HTTPException(
            status_code=428,
            detail="Initial setup required. Use /setup endpoint first.",
        )

    async with async_session() as session:
        result = await session.execute(
            select(AdminUser).where(AdminUser.email == req.email, AdminUser.is_active == True)
        )
        admin = result.scalar_one_or_none()

        if not admin or not verify_password(req.password, admin.password_hash):
            raise HTTPException(status_code=401, detail="Invalid email or password")

        token = create_access_token({"sub": admin.email})
        return LoginResponse(access_token=token, email=admin.email)


@router.post("/verify", response_model=TokenVerifyResponse)
async def verify_token_endpoint(token: str):
    """Verify if a token is still valid."""
    try:
        payload = decode_token(token)
        return TokenVerifyResponse(valid=True, email=payload.get("sub"))
    except Exception:
        return TokenVerifyResponse(valid=False)
