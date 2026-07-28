"""
Modelos ORM SQLAlchemy do Core
GovSec Shield — Infrastructure DB Models
"""

from datetime import datetime
from uuid import UUID, uuid4
from sqlalchemy import String, DateTime, Enum as SQLEnum
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from src.core.domain.entities import TenantStatus

class Base(DeclarativeBase):
    pass

class TenantModel(Base):
    """Modelo relacional para a tabela tenants."""
    __tablename__ = "tenants"

    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    slug: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    status: Mapped[TenantStatus] = mapped_column(
        SQLEnum(TenantStatus, name="tenant_status_enum", native_enum=False),
        nullable=False,
        default=TenantStatus.ACTIVE
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
