from pydantic import BaseModel
from datetime import datetime


class StatsResponse(BaseModel):
    total_cves: int
    by_severity: dict[str, int]
    latest_published_at: datetime | None
    latest_modified_at: datetime | None
