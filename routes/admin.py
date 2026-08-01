"""Admin endpoints for managing licenses (multi-app)."""
import secrets
import uuid
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from sqlalchemy import select, func

from db import async_session
from models import License, MachineActivation, ValidationLog

router = APIRouter()


# --- Schemas ---

class CreateLicenseRequest(BaseModel):
    customer_name: str
    customer_email: str
    plan: str = "starter"  # starter, pro, enterprise
    product: str  # required — specify which app this license is for
    max_machines: int = 1
    expires_at: Optional[str] = None  # ISO format, None = lifetime
    notes: Optional[str] = None


class UpdateLicenseRequest(BaseModel):
    is_active: Optional[bool] = None
    plan: Optional[str] = None
    max_machines: Optional[int] = None
    expires_at: Optional[str] = None
    notes: Optional[str] = None


class LicenseResponse(BaseModel):
    id: str
    license_key: str
    customer_name: str
    customer_email: str
    plan: str
    product: str
    max_machines: int
    is_active: bool
    expires_at: Optional[str]
    created_at: Optional[str]
    active_machines: int = 0


class StatsResponse(BaseModel):
    total_licenses: int
    active_licenses: int
    total_validations_today: int
    total_machines: int


# --- Endpoints ---

@router.post("/licenses", response_model=LicenseResponse, status_code=201)
async def create_license(req: CreateLicenseRequest):
    """Create a new license key."""
    # Generate unique license key: PREFIX-XXXX-XXXX-XXXX (prefix = product name uppercase)
    prefix = req.product.upper().replace(" ", "")[:6]
    license_key = f"{prefix}-{secrets.token_hex(4).upper()}-{secrets.token_hex(4).upper()}-{secrets.token_hex(4).upper()}"

    expires_at = None
    if req.expires_at:
        expires_at = datetime.fromisoformat(req.expires_at)

    async with async_session() as session:
        license = License(
            id=str(uuid.uuid4()),
            license_key=license_key,
            customer_name=req.customer_name,
            customer_email=req.customer_email,
            plan=req.plan,
            product=req.product,
            max_machines=req.max_machines,
            expires_at=expires_at,
            notes=req.notes,
        )
        session.add(license)
        await session.commit()

        return LicenseResponse(
            id=license.id,
            license_key=license_key,
            customer_name=req.customer_name,
            customer_email=req.customer_email,
            plan=req.plan,
            product=req.product,
            max_machines=req.max_machines,
            is_active=True,
            expires_at=req.expires_at,
            created_at=license.created_at.isoformat() if license.created_at else None,
        )


@router.get("/licenses")
async def list_licenses(
    page: int = 1,
    per_page: int = 50,
    active_only: bool = False,
):
    """List all licenses."""
    async with async_session() as session:
        query = select(License).order_by(License.created_at.desc())
        if active_only:
            query = query.where(License.is_active == True)

        # Count
        count_q = select(func.count(License.id))
        if active_only:
            count_q = count_q.where(License.is_active == True)
        total = (await session.execute(count_q)).scalar()

        # Paginate
        offset = (page - 1) * per_page
        query = query.offset(offset).limit(per_page)
        result = await session.execute(query)
        licenses = result.scalars().all()

        return {
            "total": total,
            "page": page,
            "data": [l.to_dict() for l in licenses],
        }


@router.get("/licenses/{license_id}")
async def get_license(license_id: str):
    """Get license details with machine activations."""
    async with async_session() as session:
        result = await session.execute(select(License).where(License.id == license_id))
        license = result.scalar_one_or_none()
        if not license:
            raise HTTPException(status_code=404, detail="License not found.")

        # Get machines
        machines_result = await session.execute(
            select(MachineActivation).where(MachineActivation.license_id == license_id)
        )
        machines = machines_result.scalars().all()

        return {
            **license.to_dict(),
            "machines": [
                {
                    "id": m.id,
                    "machine_id": m.machine_id,
                    "hostname": m.hostname,
                    "os_info": m.os_info,
                    "ip_address": m.ip_address,
                    "first_seen": m.first_seen.isoformat() if m.first_seen else None,
                    "last_seen": m.last_seen.isoformat() if m.last_seen else None,
                    "is_active": m.is_active,
                }
                for m in machines
            ],
        }


@router.patch("/licenses/{license_id}")
async def update_license(license_id: str, req: UpdateLicenseRequest):
    """Update license properties."""
    async with async_session() as session:
        result = await session.execute(select(License).where(License.id == license_id))
        license = result.scalar_one_or_none()
        if not license:
            raise HTTPException(status_code=404, detail="License not found.")

        if req.is_active is not None:
            license.is_active = req.is_active
        if req.plan is not None:
            license.plan = req.plan
        if req.max_machines is not None:
            license.max_machines = req.max_machines
        if req.expires_at is not None:
            license.expires_at = datetime.fromisoformat(req.expires_at)
        if req.notes is not None:
            license.notes = req.notes

        await session.commit()
        return license.to_dict()


@router.delete("/licenses/{license_id}")
async def revoke_license(license_id: str):
    """Revoke (deactivate) a license."""
    async with async_session() as session:
        result = await session.execute(select(License).where(License.id == license_id))
        license = result.scalar_one_or_none()
        if not license:
            raise HTTPException(status_code=404, detail="License not found.")

        license.is_active = False
        await session.commit()
        return {"revoked": True}


@router.get("/stats", response_model=StatsResponse)
async def get_stats():
    """Get license system statistics."""
    async with async_session() as session:
        total = (await session.execute(select(func.count(License.id)))).scalar()
        active = (await session.execute(
            select(func.count(License.id)).where(License.is_active == True)
        )).scalar()

        today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
        validations_today = (await session.execute(
            select(func.count(ValidationLog.id)).where(ValidationLog.timestamp >= today_start)
        )).scalar()

        total_machines = (await session.execute(
            select(func.count(MachineActivation.id)).where(MachineActivation.is_active == True)
        )).scalar()

        return StatsResponse(
            total_licenses=total,
            active_licenses=active,
            total_validations_today=validations_today,
            total_machines=total_machines,
        )


@router.get("/validation-logs")
async def get_validation_logs(limit: int = 50, offset: int = 0):
    """Get recent validation logs."""
    async with async_session() as session:
        result = await session.execute(
            select(ValidationLog)
            .order_by(ValidationLog.timestamp.desc())
            .offset(offset)
            .limit(limit)
        )
        logs = result.scalars().all()

        return [
            {
                "id": log.id,
                "license_id": log.license_id,
                "license_key": log.license_key,
                "machine_id": log.machine_id,
                "result": log.result,
                "ip_address": log.ip_address,
                "timestamp": log.timestamp.isoformat() if log.timestamp else None,
            }
            for log in logs
        ]
