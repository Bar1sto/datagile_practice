from fastapi import (
    APIRouter,
    Request,
    Depends,
    Query,
    HTTPException,
)
from datetime import datetime, time
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from app.db.database import get_db
from app.repositories.cve import (
    list_cves,
    count_cves,
    get_by_cve_id,
    count_cves_severity,
    count_all_cves,
)
from app.repositories.stats import get_cve_date_stats
from starlette.responses import Response


router = APIRouter(
    prefix="/ui",
    tags=["ui"],
)

templates = Jinja2Templates(directory="app/templates")


@router.get("/cve")
def get_cve(
    request: Request,
    db: Session = Depends(get_db),
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    vendor: str | None = None,
    product: str | None = None,
    published_from: str | None = None,
    published_to: str | None = None,
    severity: str | None = None,
) -> Response:
    if severity == "":
        severity = None
    if product == "":
        product = None
    if vendor == "":
        vendor = None

    published_from_dt = (
        datetime.combine(published_from, time.min) if published_from else None
    )
    published_to_dt = datetime.combine(published_to, time.max) if published_to else None
    cves = list_cves(
        db=db,
        limit=limit,
        offset=offset,
        vendor=vendor,
        product=product,
        severity=severity,
        published_from=published_from_dt,
        published_to=published_to_dt,
    )
    total = count_cves(
        db=db,
        vendor=vendor,
        product=product,
        severity=severity,
        published_from=published_from_dt,
        published_to=published_to_dt,
    )
    has_prev = offset > 0
    has_next = offset + total < total
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
            "published_from": published_from.isoformat() if published_from else "",
            "published_to": published_to.isoformat() if published_to else "",
        },
    )


@router.get("/cve/{cve_id}")
def get_cve_id(
    request: Request, cve_id: str, db: Session = Depends(get_db)
) -> Response:
    cve = get_by_cve_id(cve_id=cve_id, db=db)
    if cve is None:
        raise HTTPException(status_code=404, detail="Cve not found")
    return templates.TemplateResponse(
        request=request,
        name="cve_detail.html",
        context={"cve": cve},
    )


@router.get("/stats")
def get_cve_stats(request: Request, db: Session = Depends(get_db)) -> Response:
    total_cves = count_all_cves(
        db=db,
    )
    by_severity = count_cves_severity(
        db=db,
    )
    latest_published_at, latest_modified_at = get_cve_date_stats(db=db)
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
