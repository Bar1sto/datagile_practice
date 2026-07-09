from fastapi import (
    APIRouter,
    Depends,
)
from sqlalchemy.ext.asyncio import AsyncSession
from app.db.async_database import get_async_db
from app.repositories.async_stats import (
    count_all_cves_async,
    count_cves_severity_async,
    get_cve_date_stats_async,
)
from app.schemas.stats import StatsResponse

router = APIRouter(
    prefix="/stats",
    tags=["stats"],
)


@router.get(
    "/",
    response_model=StatsResponse,
    summary="Get CVE statistics",
    description=(
        "Get CVE statistics, including total count, "
        "counts be severity, latest published date and latest modified date"
    ),
)
async def get_stats(db: AsyncSession = Depends(get_async_db)) -> StatsResponse:
    total_cves = await count_all_cves_async(db=db)
    by_severity = await count_cves_severity_async(db=db)
    latest_published_at, latest_modified_at = await get_cve_date_stats_async(db=db)
    return StatsResponse(
        total_cves=total_cves,
        by_severity=by_severity,
        latest_published_at=latest_published_at,
        latest_modified_at=latest_modified_at,
    )
