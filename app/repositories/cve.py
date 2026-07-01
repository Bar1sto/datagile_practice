from dataclasses import dataclass
from datetime import datetime
from sqlalchemy.orm import Session
from sqlalchemy import select, func
from typing import Any, Literal
from app.models.cve import CveRecord


@dataclass
class CveUpsertResult:
    record: CveRecord
    created: bool


def get_by_cve_id(db: Session, cve_id: str) -> CveRecord | None:
    select_cve_id = select(CveRecord).where(CveRecord.cve_id == cve_id)
    result = db.execute(select_cve_id)
    return result.scalar_one_or_none()


def upsert_cve(db: Session, cve_data: dict[str, Any]) -> CveUpsertResult:
    cve_id = cve_data["cve_id"]
    existing = get_by_cve_id(db, cve_id)
    if existing is None:
        obj = CveRecord(**cve_data)
        db.add(obj)
        return CveUpsertResult(record=obj, created=True)
    else:
        for key, value in cve_data.items():
            setattr(existing, key, value)
        return CveUpsertResult(record=existing, created=False)


def list_cves(
    db: Session,
    limit: int,
    offset: int,
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] | None,
    published_from: datetime | None,
    published_to: datetime | None,
) -> list[CveRecord]:
    select_cves = select(CveRecord)
    if severity is not None:
        select_cves = select_cves.where(CveRecord.cvss_base_severity == severity)

    if published_from is not None:
        select_cves = select_cves.where(CveRecord.published_at >= published_from)

    if published_to is not None:
        select_cves = select_cves.where(CveRecord.published_at <= published_to)

    select_cves = (
        select_cves.order_by(CveRecord.published_at.desc(), CveRecord.cve_id.asc())
        .offset(offset)
        .limit(limit)
    )
    result = db.execute(select_cves)
    return list(result.scalars().all())


def count_cves(
    db: Session,
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] | None,
    published_from: datetime | None,
    published_to: datetime | None,
) -> int:
    count_records = select(func.count()).select_from(CveRecord)
    if severity is not None:
        count_records = count_records.where(CveRecord.cvss_base_severity == severity)
    if published_from is not None:
        count_records = count_records.where(CveRecord.published_at >= published_from)
    if published_to is not None:
        count_records = count_records.where(CveRecord.published_at <= published_to)
    result = db.execute(count_records)
    return result.scalar_one()


def count_cves_severity(
    db: Session,
) -> dict[str, int]:
    state = select(CveRecord.cvss_base_severity, func.count())
    state = state.select_from(CveRecord)
    state = state.group_by(CveRecord.cvss_base_severity)
    result = db.execute(state)
    dict_count = {}
    for severity, count in result:
        if severity is None:
            key = "UNKNOWN"
        else:
            key = severity
        dict_count[key] = count
    return dict_count


def count_all_cves(db: Session) -> int:
    count_records = select(func.count()).select_from(CveRecord)
    res = db.execute(count_records)
    return res.scalar_one()
