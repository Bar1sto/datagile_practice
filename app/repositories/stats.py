from datetime import datetime

from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.cve import CveRecord


async def count_all_cves_async(
    db: AsyncSession,
) -> int:
    statement = select(func.count()).select_from(CveRecord)
    result = await db.execute(statement)
    return result.scalar_one()


async def count_cves_severity_async(
    db: AsyncSession,
) -> dict[str, int]:
    statement = (
        select(CveRecord.cvss_base_severity, func.count())
        .select_from(CveRecord)
        .group_by(CveRecord.cvss_base_severity)
    )
    result = await db.execute(statement)
    count_by_severity: dict[str, int] = {}
    for severity, count in result:
        key = "UNKNOW" if severity is None else severity
        count_by_severity[key] = count
    return count_by_severity


async def get_cve_date_stats_async(
    db: AsyncSession,
) -> tuple[datetime | None, datetime | None]:
    statement = select(
        func.max(CveRecord.published_at),
        func.max(CveRecord.last_modified_at),
    )
    result = await db.execute(statement)
    row = result.one()
    latest_published_at = row[0]
    latest_modified_at = row[1]
    return latest_published_at, latest_modified_at
