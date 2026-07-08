from typing import Literal
from datetime import datetime
from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Query,
    Path,
)
from sqlalchemy.orm import Session
from app.db.database import get_db
from app.repositories.cve import (
    get_by_cve_id,
    list_cves,
    count_cves,
)
from app.schemas.cve import (
    CVEDetailResponse,
    CVEPaginatedResponse,
    CVEListItemResponse,
)
from app.schemas.error import (
    ErrorResponse,
)
from app.api.errors import error_detail


router = APIRouter(
    prefix="/cve",
    tags=["cve"],
)


@router.get(
    "/{cve_id}",
    response_model=CVEDetailResponse,
    summary="Get cve details",
    description="Returns full info about a CVE, including CVSS data and affected products ",
    responses={
        404: {
            "model": ErrorResponse,
            "description": "CVE not found",
        }
    },
)
def get_cve_id(
    cve_id: str = Path(
        ...,
        description="CVE identifier in the format CVE-YYYY-NNNN",
        example="CVE-2024-34065",
    ),
    db: Session = Depends(get_db),
) -> CVEDetailResponse:
    cve = get_by_cve_id(db, cve_id)
    if cve is None:
        raise HTTPException(
            status_code=404,
            detail=error_detail("CVE_NOT_FOUND", "CVE not found"),
        )
    return CVEDetailResponse.model_validate(cve)


@router.get(
    "/",
    response_model=CVEPaginatedResponse,
    summary="List CVEs",
    description=(
        "Returns paginated CVE records with optional filters by severity, "
        "publication date range, vendor and product"
    ),
    responses={
        400: {
            "model": ErrorResponse,
            "description": "Invalid date range",
        }
    },
)
def get_all_cve(
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] | None = Query(
        default=None,
        description="Filter Cves be CVSS severity",
        example="LOW",
    ),
    published_from: datetime | None = Query(
        default=None,
        description="Return CVEs published at or after this datetime",
        example="2026-07-01T00:00Z",
    ),
    published_to: datetime | None = Query(
        default=None,
        description="Return CVEs published at or before this datetime",
        example="2026-07-07T23:59:59Z",
    ),
    db: Session = Depends(get_db),
    limit: int = Query(
        default=20,
        ge=1,
        le=100,
        description="Maximum number of CVEs to return",
        example=20,
    ),
    offset: int = Query(
        default=0,
        ge=0,
        description="Number of CVEs to skip before returning results",
        example=0,
    ),
    vendor: str | None = Query(
        default=None,
        description="Filter by affected product vendor or ecosystem",
        example="Dell",
    ),
    product: str | None = Query(
        default=None,
        description="Filter by affected product name",
        example="PowerProtect",
    ),
) -> CVEPaginatedResponse:
    if (published_from is not None and published_to is not None) and (
        published_to < published_from
    ):
        raise HTTPException(
            status_code=400,
            detail=error_detail(
                "INVALID_DATE_RANGE",
                "published_from must be less than or equal to published_to",
            ),
        )
    records = list_cves(
        db, limit, offset, severity, published_from, published_to, vendor, product
    )
    items = [CVEListItemResponse.model_validate(record) for record in records]
    return CVEPaginatedResponse(
        items=items,
        total=count_cves(db, severity, published_from, published_to, vendor, product),
        limit=limit,
        offset=offset,
    )
