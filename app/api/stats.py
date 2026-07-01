from fastapi import (
    APIRouter,
    Depends,
)
from app.repositories.cve import count_cves_severity, count_all_cves
from sqlalchemy.orm import Session
from app.repositories.stats import get_cve_date_stats
from app.db.database import get_db
from app.schemas.stats import StatsResponse

router = APIRouter(
    prefix="/stats",
    tags=["stats"],
)


@router.get("/", response_model=StatsResponse)
def get_stats_severity(db: Session = Depends(get_db)) -> StatsResponse:
    total_cves = count_all_cves(db)
    by_severity = count_cves_severity(db)
    latest_published_at, latest_modified_at = get_cve_date_stats(db)
    return StatsResponse(
        total_cves=total_cves,
        by_severity=by_severity,
        latest_published_at=latest_published_at,
        latest_modified_at=latest_modified_at,
    )
