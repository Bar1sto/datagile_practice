from sqlalchemy.orm import Session
from sqlalchemy import select
from typing import Any
from app.models.cve_model import CveRecord


def get_by_cve_id(db: Session, cve_id: str) -> CveRecord | None:
    select_cve_id = select(CveRecord).where(CveRecord.cve_id == cve_id)
    result = db.execute(select_cve_id)
    return result.scalar_one_or_none()


def upsert_cve(db: Session, cve_data: dict[str, Any]) -> CveRecord:
    cve_id = cve_data["cve_id"]
    existing = get_by_cve_id(db, cve_id)
    if existing is None:
        obj = CveRecord(**cve_data)
        db.add(obj)
        return obj
    else:
        for key, value in cve_data.items():
            setattr(existing, key, value)
        return existing
