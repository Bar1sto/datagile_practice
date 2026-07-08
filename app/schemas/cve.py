from datetime import datetime
from decimal import Decimal
from pydantic import BaseModel, ConfigDict, Field
from typing import Literal


class CveAffectedProductResponse(BaseModel):
    vendor: str = Field(description="Affected product vendor, supplier, or ecosystem")
    product: str = Field(description="Affected product or package name")
    version: str | None = Field(
        description="Affected version or version range, if available"
    )
    cpe_uri: str | None = Field(
        description="CPE URI for the affected product, if available"
    )

    model_config = ConfigDict(from_attributes=True)


class CVEDetailResponse(BaseModel):
    cve_id: str = Field(description="CVE identifier")
    source_identifier: str | None = Field(
        description="Primary source that first created the CVE record"
    )
    published_at: datetime = Field(description="Datetime when the CVE was published")
    last_modified_at: datetime = Field(
        description="Datetime when the CVE was last modified"
    )
    vuln_status: str | None = Field(
        description="Vulnerability status from the source, if available"
    )
    description: str | None = Field(description="Vulnerability description")
    cvss_base_score: Decimal | None = Field(description="CVSS base score, if available")
    cvss_base_severity: str | None = Field(
        description="CVSS base severity, if available"
    )
    cvss_vector: str | None = Field(description="CVSS vector string, if available")
    affected_products: list[CveAffectedProductResponse] = Field(
        description="Affected products linked to this CVE"
    )
    created_at: datetime = Field(
        description="Datetime when the record was created in the local database"
    )
    updated_at: datetime = Field(
        description="Datetime when the record was last updated in the local database"
    )

    model_config = ConfigDict(from_attributes=True)


class CVEListItemResponse(BaseModel):
    cve_id: str = Field(description="CVE identifier")
    published_at: datetime = Field(description="Datetime when the CVE was published")
    last_modified_at: datetime = Field(
        description="Datetime when the CVE was last modified"
    )
    description: str | None = Field(description="Short vulnerability description")
    cvss_base_score: Decimal | None = Field(description="CVSS base score, if available")
    cvss_base_severity: str | None = Field(
        description="CVSS base severity, if available"
    )

    model_config = ConfigDict(from_attributes=True)


class CVEPaginatedResponse(BaseModel):
    items: list[CVEListItemResponse] = Field(
        description="List of CVE records for the current page"
    )
    total: int = Field(
        ge=0, description="Total number of CVE records matching the filters"
    )
    limit: int = Field(ge=1, le=100, description="Maximum number of records returned")
    offset: int = Field(
        ge=0, description="Number of records skipped before the current page"
    )


class CVEFilterParams(BaseModel):
    vendor: str | None = Field(default=None, min_length=1, max_length=255)
    product: str | None = Field(default=None, min_length=1, max_length=255)
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] | None = None
    published_from: datetime | None = None
    published_to: datetime | None = None
    limit: int = Field(default=20, ge=1, le=100)
    offset: int = Field(default=0, ge=0)
