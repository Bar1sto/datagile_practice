from datetime import datetime
from decimal import Decimal
from uuid import UUID
from pydantic import BaseModel, ConfigDict


class CVEDetailResponse(BaseModel):
    id: UUID
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
