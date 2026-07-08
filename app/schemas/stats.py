from pydantic import BaseModel, Field
from datetime import datetime


class StatsResponse(BaseModel):
    total_cves: int = Field(description="Total number of CVE records in the database")
    by_severity: dict[str, int] = Field(
        description="Number of CVEs grouped by severity"
    )
    latest_published_at: datetime | None = Field(
        description="Latest CVE publication datetime"
    )
    latest_modified_at: datetime | None = Field(
        description="Latest CVE modification datetime"
    )
