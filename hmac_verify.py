"""
HMAC Request Signing Verification.

Client apps sign requests with shared secret.
License Manager verifies signature to prevent tampering/replay.

Header format:
  X-Signature: <hmac_hex>
  X-Timestamp: <unix_timestamp>

Signature = HMAC-SHA256(secret, f"{timestamp}:{method}:{path}:{body}")
Replay window: 5 minutes
"""
import hashlib
import hmac
import time
from typing import Optional

from fastapi import Request, HTTPException
from loguru import logger

from config import settings

# Max age of request signature (5 minutes)
MAX_SIGNATURE_AGE = 300


def compute_signature(timestamp: str, method: str, path: str, body: str = "") -> str:
    """Compute HMAC-SHA256 signature."""
    message = f"{timestamp}:{method}:{path}:{body}".encode()
    return hmac.new(
        settings.SECRET_KEY.encode(),
        message,
        hashlib.sha256,
    ).hexdigest()


async def verify_hmac_signature(request: Request) -> Optional[bool]:
    """
    Verify HMAC signature on incoming request.

    Returns True if valid, raises HTTPException if invalid.
    Skips verification if no signature header present (backward compat).
    """
    signature = request.headers.get("X-Signature")
    timestamp = request.headers.get("X-Timestamp")

    # If no signature headers, allow (backward compatibility)
    # In strict mode, you'd reject unsigned requests
    if not signature or not timestamp:
        return None  # Not signed, allow for now

    # Check replay window
    try:
        req_time = int(timestamp)
        now = int(time.time())
        if abs(now - req_time) > MAX_SIGNATURE_AGE:
            logger.warning(f"Signature expired: age={now - req_time}s from {request.client.host}")
            raise HTTPException(status_code=401, detail="Request signature expired")
    except ValueError:
        raise HTTPException(status_code=401, detail="Invalid timestamp")

    # Read body
    body = await request.body()
    body_str = body.decode() if body else ""

    # Compute expected signature
    expected = compute_signature(
        timestamp,
        request.method,
        request.url.path,
        body_str,
    )

    if not hmac.compare_digest(signature, expected):
        logger.warning(f"Invalid signature from {request.client.host} on {request.url.path}")
        raise HTTPException(status_code=401, detail="Invalid request signature")

    return True
