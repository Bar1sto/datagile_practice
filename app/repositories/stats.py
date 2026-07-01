from sqlalchemy.orm import Session
from datetime import datetime
from sqlalchemy.sql import select, func
from app.models.cve import CveRecord


def get_cve_date_stats(db: Session) -> tuple[datetime | None, datetime | None]:
    select_date = select(
        func.max(CveRecord.published_at), func.max(CveRecord.last_modified_at)
    )
    result = db.execute(select_date)
    row = result.one()
    latest_published_at = row[0]
    latest_modified_at = row[1]
    return latest_published_at, latest_modified_at
