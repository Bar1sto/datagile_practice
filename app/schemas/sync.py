from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class SyncRunResponse(BaseModel):
    id: UUID
    source: str
    status: str
    added_count: int
    updated_count: int
    started_at: datetime
    finished_at: datetime | None
    model_config = ConfigDict(from_attributes=True)


class SyncRunPaginatedResponse(BaseModel):
    items: list[SyncRunResponse]
    total: int
    limit: int
    offset: int
