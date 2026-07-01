from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy.sql import select, func
from sqlalchemy.orm import Session
from app.models.sync import SyncRun


def create_sync_run(db: Session, source: str) -> SyncRun:
    sync_run = SyncRun(source=source, status="running")
    db.add(sync_run)
    return sync_run


def mark_sync_run_success(
    sync_run: SyncRun, added_count: int, updated_count: int
) -> SyncRun:
    sync_run.status = "success"
    sync_run.added_count = added_count
    sync_run.updated_count = updated_count
    sync_run.finished_at = datetime.now(timezone.utc)
    return sync_run


def mark_sync_run_failed(sync_run: SyncRun) -> SyncRun:
    sync_run.status = "failed"
    sync_run.finished_at = datetime.now(timezone.utc)
    return sync_run


def list_sync_runs(db: Session, offset: int, limit: int) -> list[SyncRun]:
    state = select(SyncRun)
    state = state.order_by(SyncRun.started_at.desc())
    state = state.offset(offset).limit(limit)
    result = db.execute(state)
    return list(result.scalars().all())


def count_sync_runs(db: Session) -> int:
    state = select(func.count()).select_from(SyncRun)
    result = db.execute(state)
    return result.scalar_one()


def get_sync_run_id(db: Session, sync_run_id: UUID) -> SyncRun | None:
    state = select(SyncRun).where(SyncRun.id == sync_run_id)
    if state is None:
        return None
    result = db.execute(state)
    return result.scalar_one_or_none()
