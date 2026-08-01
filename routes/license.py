"""License validation endpoints — called by client apps."""
import json
import logging
from datetime import datetime

from cryptography.hazmat.primitives.serialization import load_der_private_key
from fastapi import APIRouter, Request
from pydantic import BaseModel
from sqlalchemy import select, func

from config import settings
from db import async_session
from models import License, MachineActivation, ValidationLog

logger = logging.getLogger(__name__)

router = APIRouter()

# Load Ed25519 private key for signing responses
_signing_key = None
if settings.LICENSE_SIGNING_PRIVATE_KEY:
    _signing_key = load_der_private_key(
        bytes.fromhex(settings.LICENSE_SIGNING_PRIVATE_KEY),
        password=None,
    )


def _sign_response(payload: dict) -> str:
    """Sign canonical JSON of payload (excluding signature field) with Ed25519."""
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    sig = _signing_key.sign(canonical.encode())
    return sig.hex()


def _signed_response(payload: dict) -> dict:
    """Add nonce + signature to a response dict."""
    if _signing_key:
        payload["signature"] = _sign_response(payload)
    return payload


class ValidateRequest(BaseModel):
    license_key: str
    machine_id: str
    product: str  # required — app must identify itself
    version: str = ""
    hostname: str = ""
    os_info: str = ""
    nonce: str = ""  # client-generated random hex, echoed back in response


class ValidateResponse(BaseModel):
    valid: bool
    plan: str | None = None
    expires_at: str | None = None
    message: str = ""
    nonce: str = ""
    signature: str = ""


@router.post("/validate")
async def validate_license(req: ValidateRequest, request: Request):
    """
    Validate a license key from client.

    Checks:
    1. License exists and is active
    2. License not expired
    3. Machine count within limit

    Response is Ed25519-signed (signature field) with nonce echoed back.
    """
    client_ip = request.client.host if request.client else None

    def resp(**kw) -> dict:
        payload = {"nonce": req.nonce, **kw}
        if _signing_key:
            payload["signature"] = _sign_response(payload)
        return payload

    async with async_session() as session:
        # Find license
        result = await session.execute(
            select(License).where(License.license_key == req.license_key)
        )
        license = result.scalar_one_or_none()

        if not license:
            await _log_validation(session, None, req.license_key, req.machine_id, "invalid", client_ip)
            return resp(valid=False, message="License key not found.")

        if not license.is_active:
            await _log_validation(session, license.id, req.license_key, req.machine_id, "inactive", client_ip)
            return resp(valid=False, message="License has been deactivated.")

        # Check product match
        if license.product != req.product:
            await _log_validation(session, license.id, req.license_key, req.machine_id, "wrong_product", client_ip)
            return resp(valid=False, message="License not valid for this product.")

        # Check expiry
        if license.expires_at and datetime.utcnow() > license.expires_at:
            await _log_validation(session, license.id, req.license_key, req.machine_id, "expired", client_ip)
            return resp(
                valid=False,
                expires_at=license.expires_at.isoformat(),
                message="License has expired.",
            )

        # Check machine limit
        machine_count_result = await session.execute(
            select(func.count(MachineActivation.id)).where(
                MachineActivation.license_id == license.id,
                MachineActivation.is_active == True,
            )
        )
        active_machines = machine_count_result.scalar()

        # Check if this machine is already registered (by machine_id)
        existing_machine = await session.execute(
            select(MachineActivation).where(
                MachineActivation.license_id == license.id,
                MachineActivation.machine_id == req.machine_id,
                MachineActivation.is_active == True,
            )
        )
        machine = existing_machine.scalar_one_or_none()

        # Also check by IP — same IP = same machine (handles container recreate / machine_id change)
        machine_by_ip = None
        if not machine and client_ip:
            ip_result = await session.execute(
                select(MachineActivation).where(
                    MachineActivation.license_id == license.id,
                    MachineActivation.ip_address == client_ip,
                    MachineActivation.is_active == True,
                )
            )
            machine_by_ip = ip_result.scalar_one_or_none()

        if machine:
            # Exact machine_id match — update info
            machine.last_seen = datetime.utcnow()
            machine.hostname = req.hostname or machine.hostname
            machine.os_info = req.os_info or machine.os_info
            machine.ip_address = client_ip or machine.ip_address
            await session.commit()
        elif machine_by_ip:
            # Same IP, different machine_id — treat as same machine (e.g. container recreated)
            machine_by_ip.machine_id = req.machine_id  # Update to new machine_id
            machine_by_ip.last_seen = datetime.utcnow()
            machine_by_ip.hostname = req.hostname or machine_by_ip.hostname
            machine_by_ip.os_info = req.os_info or machine_by_ip.os_info
            await session.commit()
            logger.info(f"Machine re-identified by IP {client_ip}. Updated machine_id.")
        else:
            # Truly new machine - check limit
            if active_machines >= license.max_machines:
                await _log_validation(session, license.id, req.license_key, req.machine_id, "machine_limit", client_ip)
                return resp(
                    valid=False,
                    message=f"Machine limit reached ({license.max_machines}). Deactivate another machine first.",
                )

            # Register new machine
            new_machine = MachineActivation(
                license_id=license.id,
                machine_id=req.machine_id,
                hostname=req.hostname,
                os_info=req.os_info,
                ip_address=client_ip,
            )
            session.add(new_machine)
            await session.commit()

        # Valid!
        await _log_validation(session, license.id, req.license_key, req.machine_id, "valid", client_ip)

        return resp(
            valid=True,
            plan=license.plan,
            expires_at=license.expires_at.isoformat() if license.expires_at else None,
            message="License valid.",
        )


@router.post("/deactivate")
async def deactivate_machine(req: ValidateRequest):
    """Deactivate a machine from a license (free up slot)."""
    async with async_session() as session:
        result = await session.execute(
            select(License).where(License.license_key == req.license_key)
        )
        license = result.scalar_one_or_none()
        if not license:
            return {"success": False, "message": "License not found."}

        machine_result = await session.execute(
            select(MachineActivation).where(
                MachineActivation.license_id == license.id,
                MachineActivation.machine_id == req.machine_id,
                MachineActivation.is_active == True,
            )
        )
        machines = machine_result.scalars().all()
        if machines:
            for machine in machines:
                machine.is_active = False
            await session.commit()
            return {"success": True, "message": "Machine deactivated."}

        return {"success": False, "message": "Machine not found or already deactivated."}


async def _log_validation(session, license_id, license_key, machine_id, result, ip):
    """Log validation attempt."""
    log = ValidationLog(
        license_id=license_id,
        license_key=license_key,
        machine_id=machine_id,
        result=result,
        ip_address=ip,
    )
    session.add(log)
    await session.commit()
