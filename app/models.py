from uuid import uuid4

from sqlalchemy import ForeignKey, Index, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base
from .security import now_ts


def new_uuid() -> str:
    return str(uuid4())


class User(Base):
    __tablename__ = 'users'
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    email: Mapped[str] = mapped_column(String(255), nullable=False, unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    is_admin: Mapped[bool] = mapped_column(default=False, nullable=False)
    is_active: Mapped[bool] = mapped_column(default=True, nullable=False)
    created_at: Mapped[int] = mapped_column(default=now_ts, nullable=False)
    keys: Mapped[list['LicenseKey']] = relationship(back_populates='owner')


class RefreshSession(Base):
    __tablename__ = 'refresh_sessions'
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    user_id: Mapped[str] = mapped_column(ForeignKey('users.id'), index=True)
    token_digest: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    expires_at: Mapped[int] = mapped_column(nullable=False)
    revoked_at: Mapped[int | None] = mapped_column(nullable=True)
    created_at: Mapped[int] = mapped_column(default=now_ts, nullable=False)


class LicenseKey(Base):
    __tablename__ = 'license_keys'
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    owner_id: Mapped[str] = mapped_column(ForeignKey('users.id'), nullable=False, index=True)
    prefix: Mapped[str] = mapped_column(String(24), unique=True, nullable=False, index=True)
    key_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    note: Mapped[str] = mapped_column(String(200), default='', nullable=False)
    device_limit: Mapped[int] = mapped_column(default=1, nullable=False)
    expires_at: Mapped[int] = mapped_column(nullable=False)
    revoked_at: Mapped[int | None] = mapped_column(nullable=True)
    created_at: Mapped[int] = mapped_column(default=now_ts, nullable=False)
    owner: Mapped[User] = relationship(back_populates='keys')
    devices: Mapped[list['Activation']] = relationship(back_populates='key', cascade='all, delete-orphan')


class Activation(Base):
    __tablename__ = 'activations'
    __table_args__ = (
        UniqueConstraint('key_id', 'device_hash', name='uq_key_device'),
        Index('ix_activation_key_created', 'key_id', 'created_at'),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    key_id: Mapped[str] = mapped_column(ForeignKey('license_keys.id'), nullable=False, index=True)
    device_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    label: Mapped[str] = mapped_column(String(80), default='', nullable=False)
    created_at: Mapped[int] = mapped_column(default=now_ts, nullable=False)
    key: Mapped[LicenseKey] = relationship(back_populates='devices')


class DeviceHeartbeat(Base):
    """Last successful online verification for an enrolled device.

    Lives in a separate table to avoid altering the existing activations table.
    """
    __tablename__ = 'device_heartbeats'
    key_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    device_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    last_verified_at: Mapped[int] = mapped_column(nullable=False)


class DeviceAuditEvent(Base):
    """Small permanent audit trail of device enrollments and admin actions."""
    __tablename__ = 'device_audit_events'
    __table_args__ = (Index('ix_device_event_key_time', 'key_id', 'created_at'),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    key_id: Mapped[str] = mapped_column(String(36), nullable=False)
    device_code: Mapped[str] = mapped_column(String(24), nullable=False)
    label: Mapped[str] = mapped_column(String(80), default='', nullable=False)
    event_type: Mapped[str] = mapped_column(String(24), nullable=False)
    created_at: Mapped[int] = mapped_column(default=now_ts, nullable=False)


class APICredential(Base):
    __tablename__ = 'api_credentials'
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    owner_id: Mapped[str] = mapped_column(ForeignKey('users.id'), nullable=False, index=True)
    prefix: Mapped[str] = mapped_column(String(24), unique=True, nullable=False, index=True)
    key_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    label: Mapped[str] = mapped_column(String(80), nullable=False)
    revoked_at: Mapped[int | None] = mapped_column(nullable=True)
    created_at: Mapped[int] = mapped_column(default=now_ts, nullable=False)
    owner: Mapped[User] = relationship()
