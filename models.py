"""License database models."""
import uuid
from datetime import datetime

from sqlalchemy import Column, String, Boolean, Integer, DateTime, Text, JSON
from db import Base


class License(Base):
    __tablename__ = "licenses"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    license_key = Column(String(64), unique=True, nullable=False, index=True)
    customer_name = Column(String(200), nullable=False)
    customer_email = Column(String(200), nullable=False)
    plan = Column(String(20), nullable=False, default="starter")  # starter, pro, enterprise
    product = Column(String(50), nullable=False)  # app identifier e.g. "d2t", "peopledet"
    max_machines = Column(Integer, default=1)
    is_active = Column(Boolean, default=True)
    expires_at = Column(DateTime, nullable=True)  # None = lifetime
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    notes = Column(Text, nullable=True)

    def to_dict(self):
        return {
            "id": self.id,
            "license_key": self.license_key,
            "customer_name": self.customer_name,
            "customer_email": self.customer_email,
            "plan": self.plan,
            "product": self.product,
            "max_machines": self.max_machines,
            "is_active": self.is_active,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class MachineActivation(Base):
    __tablename__ = "machine_activations"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    license_id = Column(String(36), nullable=False, index=True)
    machine_id = Column(String(64), nullable=False)
    hostname = Column(String(200), nullable=True)
    os_info = Column(String(200), nullable=True)
    ip_address = Column(String(45), nullable=True)
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    is_active = Column(Boolean, default=True)


class ValidationLog(Base):
    __tablename__ = "validation_logs"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    license_id = Column(String(36), nullable=True)
    license_key = Column(String(64), nullable=False)
    machine_id = Column(String(64), nullable=False)
    result = Column(String(20), nullable=False)  # valid, invalid, expired, machine_limit
    ip_address = Column(String(45), nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    extra_data = Column("metadata", JSON, nullable=True)  # 'metadata' is reserved by SQLAlchemy


class AdminUser(Base):
    __tablename__ = "admin_users"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email = Column(String(200), unique=True, nullable=False)
    password_hash = Column(String(200), nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
