from typing import Literal
from datetime import datetime
from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Query,
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
    responses={
        404: {
            "model": ErrorResponse,
            "description": "CVE not found",
        }
    },
)
def get_cve_id(
    cve_id: str,
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
    responses={
        400: {
            "model": ErrorResponse,
            "description": "Invalid date range",
        }
    },
)
def get_all_cve(
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] | None = None,
    published_from: datetime | None = None,
    published_to: datetime | None = None,
    db: Session = Depends(get_db),
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
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
    records = list_cves(db, limit, offset, severity, published_from, published_to)
    items = [CVEListItemResponse.model_validate(record) for record in records]
    return CVEPaginatedResponse(
        items=items,
        total=count_cves(db, severity, published_from, published_to),
        limit=limit,
        offset=offset,
    )
