from datetime import datetime
from decimal import Decimal
from uuid import UUID
from pydantic import BaseModel, ConfigDict, Field
from typing import Literal


class CVEDetailResponse(BaseModel):
    id: UUID  # уточнить надо ли видить внутренний айдишник пользователю
    cve_id: str
    source_identifier: str | None
    published_at: datetime
    last_modified_at: datetime
    vuln_status: str | None
    description: str | None
    cvss_base_score: Decimal | None
    cvss_base_severity: str | None
    cvss_vector: str | None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class CVEListItemResponse(BaseModel):
    cve_id: str
    published_at: datetime
    last_modified_at: datetime
    description: str | None
    cvss_base_score: Decimal | None
    cvss_base_severity: str | None

    model_config = ConfigDict(from_attributes=True)


class CVEPaginatedResponse(BaseModel):
    items: list[CVEListItemResponse]
    total: int = Field(ge=0)
    limit: int = Field(ge=1, le=100)
    offset: int = Field(ge=0)


class CVEFilterParams(BaseModel):
    vendor: str | None = Field(default=None, min_length=1, max_length=255)
    product: str | None = Field(default=None, min_length=1, max_length=255)
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] | None = None
    published_from: datetime | None = None
    published_to: datetime | None = None
    limit: int = Field(default=20, ge=1, le=100)
    offset: int = Field(default=0, ge=0)
