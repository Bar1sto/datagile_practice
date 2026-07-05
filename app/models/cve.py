import datetime
import uuid
from app.db.database import Base
from sqlalchemy import (
    String,
    DateTime,
    Numeric,
    Text,
    func,
    ForeignKey,
)
from decimal import Decimal
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import (
    mapped_column,
    Mapped,
    relationship,
)


class CveRecord(Base):
    __tablename__ = "cve_records"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    cve_id: Mapped[str] = mapped_column(
        String(32),
        unique=True,
        index=True,
    )
    source_identifier: Mapped[str | None] = mapped_column(String(255))
    published_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True),
    )
    last_modified_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True),
    )
    vuln_status: Mapped[str | None] = mapped_column(
        String(50),
    )
    description: Mapped[str | None] = mapped_column(
        Text,
    )
    cvss_base_score: Mapped[Decimal | None] = mapped_column(
        Numeric(precision=5, scale=2),
    )
    cvss_base_severity: Mapped[str | None] = mapped_column(
        String(20),
        index=True,
    )
    cvss_vector: Mapped[str | None] = mapped_column(
        String(255),
    )
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(
            timezone=True,
        ),
        server_default=func.now(),
    )
    updated_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(
            timezone=True,
        ),
        server_default=func.now(),
        onupdate=func.now(),
    )
    affected_products: Mapped[list["CveAffectedProduct"]] = relationship(
        back_populates="cve_record",
        cascade="all, delete-orphan",
    )


class CveAffectedProduct(Base):
    __tablename__ = "cve_affected_products"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    cve_record_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey(
            "cve_records.id",
            ondelete="CASCADE",
        )
    )
    vendor: Mapped[str] = mapped_column(
        String(255),
    )
    product: Mapped[str] = mapped_column(
        String(255),
    )
    version: Mapped[str | None] = mapped_column(
        String(255),
    )
    cpe_uri: Mapped[str | None] = mapped_column(
        String(500),
    )
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
    )
    cve_record: Mapped["CveRecord"] = relationship(back_populates="affected_products")
