from datetime import datetime
from uuid import UUID
from pydantic import BaseModel, ConfigDict, Field


class SyncRunResponse(BaseModel):
    id: UUID = Field(description="Unique sync run identifier")
    source: str = Field(description="Vulnerability source name, for example NVD or OSV")
    status: str = Field(
        description="Sync run status^ for example running, success or failed"
    )
    added_count: int = Field(
        description="Number of CVE records created during the sync run"
    )
    updated_count: int = Field(
        description="Number of existing CVE records updated during the sync run"
    )
    started_at: datetime = Field(description="Datetime when the sync run started")
    finished_at: datetime | None = Field(
        description="Datetime when the sync run finished or bull if it is still running"
    )
    model_config = ConfigDict(from_attributes=True)


class SyncRunPaginatedResponse(BaseModel):
    items: list[SyncRunResponse] = Field(
        description="List of sync runs the current page"
    )
    total: int = Field(description="Total number of sync runs matching the request")
    limit: int = Field(description="Maximum number of sync runs returned")
    offset: int = Field(description="Number of sync runs skipped")


class SyncResultResponse(BaseModel):
    total_count: int = Field(
        description="Total number of vulnerabilities received from the source"
    )
    added_count: int = Field(description="Number of CVE records created")
    updated_count: int = Field(description="Number of existing CVE records updated")
