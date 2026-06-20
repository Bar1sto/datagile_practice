import datetime
import uuid
from app.db.database import Base
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy import (
    String,
    Integer,
    DateTime,
    func,
)
from sqlalchemy.dialects.postgresql import UUID


class SyncRun(Base):
    __tablename__ = "sync_runs"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    source: Mapped[str] = mapped_column(
        String(100),
        default="NVD",
    )
    status: Mapped[str] = mapped_column(
        String(50),
    )
    added_count: Mapped[int] = mapped_column(Integer, default=0)
    updated_count: Mapped[int] = mapped_column(Integer, default=0)
    started_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(
            timezone=True,
        ),
        server_default=func.now(),
    )
    finished_at: Mapped[datetime.datetime | None] = mapped_column(
        DateTime(
            timezone=True,
        ),
    )
