from fastapi import (
    APIRouter,
    Request,
    Depends,
    Query,
    HTTPException,
)
from datetime import datetime, time
from fastapi.templating import Jinja2Templates
from sqlalchemy.ext.asyncio import AsyncSession
from app.db.database import get_async_db
from app.repositories.cve import (
    count_cves_async,
    get_by_cve_id_async,
    list_cves_async,
)
from app.repositories.stats import (
    count_all_cves_async,
    count_cves_severity_async,
    get_cve_date_stats_async,
)
from starlette.responses import Response


router = APIRouter(
    prefix="/ui",
    tags=["ui"],
)

templates = Jinja2Templates(directory="app/templates")


@router.get("/cve")
async def get_cve(
    request: Request,
    db: AsyncSession = Depends(get_async_db),
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    vendor: str | None = None,
    product: str | None = None,
    published_from: str | None = None,
    published_to: str | None = None,
    severity: str | None = None,
) -> Response:
    allowed_severities = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}

    if severity == "":
        severity = None
    if product == "":
        product = None
    if vendor == "":
        vendor = None

    if severity is not None and severity not in allowed_severities:
        raise HTTPException(status_code=400, detail="Invalid severity")

    published_from_date = (
        datetime.strptime(published_from, "%Y-%m-%d").date() if published_from else None
    )
    published_to_date = (
        datetime.strptime(published_to, "%Y-%m-%d").date() if published_to else None
    )

    published_from_dt = (
        datetime.combine(published_from_date, time.min) if published_from_date else None
    )
    published_to_dt = (
        datetime.combine(published_to_date, time.max) if published_to_date else None
    )

    cves = await list_cves_async(
        db=db,
        limit=limit,
        offset=offset,
        vendor=vendor,
        product=product,
        severity=severity,
        published_from=published_from_dt,
        published_to=published_to_dt,
    )
    total = await count_cves_async(
        db=db,
        vendor=vendor,
        product=product,
        severity=severity,
        published_from=published_from_dt,
        published_to=published_to_dt,
    )
    has_prev = offset > 0
    has_next = offset + limit < total
    prev_offset = max(offset - limit, 0)
    next_offset = offset + limit
    return templates.TemplateResponse(
        request=request,
        name="cve_list.html",
        context={
            "cves": cves,
            "total": total,
            "limit": limit,
            "offset": offset,
            "vendor": vendor or "",
            "product": product or "",
            "severity": severity or "",
            "has_prev": has_prev,
            "has_next": has_next,
            "prev_offset": prev_offset,
            "next_offset": next_offset,
            "published_from": published_from or "",
            "published_to": published_to or "",
        },
    )


@router.get("/cve/{cve_id}")
async def get_cve_id(
    request: Request, cve_id: str, db: AsyncSession = Depends(get_async_db)
) -> Response:
    cve = await get_by_cve_id_async(cve_id=cve_id, db=db)
    if cve is None:
        raise HTTPException(status_code=404, detail="Cve not found")
    return templates.TemplateResponse(
        request=request,
        name="cve_detail.html",
        context={"cve": cve},
    )


@router.get("/stats")
async def get_cve_stats(
    request: Request, db: AsyncSession = Depends(get_async_db)
) -> Response:
    total_cves = await count_all_cves_async(
        db=db,
    )
    by_severity = await count_cves_severity_async(
        db=db,
    )
    latest_published_at, latest_modified_at = await get_cve_date_stats_async(db=db)
    return templates.TemplateResponse(
        request=request,
        name="cve_stats.html",
        context={
            "total_cves": total_cves,
            "by_severity": by_severity,
            "latest_published_at": latest_published_at,
            "latest_modified_at": latest_modified_at,
        },
    )
