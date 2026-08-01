"""
JWT Authentication for License Manager Admin API.

- Admin endpoints require valid JWT token
- Tokens expire after configurable hours
- Password hashed with bcrypt
- First login requires password setup (no hardcoded default)
"""
from datetime import datetime, timedelta
from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy import select

from config import settings
from db import async_session
from models import AdminUser

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Bearer token scheme
security = HTTPBearer(auto_error=False)


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(hours=settings.JWT_EXPIRE_HOURS))
    to_encode.update({"exp": expire, "iat": datetime.utcnow()})
    return jwt.encode(to_encode, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


def decode_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
        return payload
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )


async def get_current_admin(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
) -> dict:
    """Dependency: require valid admin JWT."""
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    payload = decode_token(credentials.credentials)
    email = payload.get("sub")
    if not email:
        raise HTTPException(status_code=401, detail="Invalid token payload")

    return {"email": email, "token_issued": payload.get("iat")}


async def ensure_admin_exists():
    """Check if admin exists. If not, system is in 'setup' mode.
    No password is created automatically — user must set it via /setup endpoint.
    """
    async with async_session() as session:
        result = await session.execute(select(AdminUser).limit(1))
        if result.scalar_one_or_none() is None:
            from loguru import logger
            logger.warning("No admin user found. First-login setup required at /api/v1/admin/auth/setup")


async def is_setup_required() -> bool:
    """Check if system needs initial setup (no admin exists)."""
    async with async_session() as session:
        result = await session.execute(select(AdminUser).limit(1))
        return result.scalar_one_or_none() is None
