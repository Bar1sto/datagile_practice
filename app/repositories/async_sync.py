from uuid import UUID
from datetime import datetime, timezone

from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.sync import SyncRun


async def list_sync_runs_async(
    db: AsyncSession,
    offset: int,
    limit: int,
) -> list[SyncRun]:
    statement = (
        select(SyncRun).order_by(SyncRun.started_at.desc()).offset(offset).limit(limit)
    )
    result = await db.execute(statement)
    return list(result.scalars().all())


async def count_sync_runs_async(
    db: AsyncSession,
) -> int:
    statement = select(func.count()).select_from(SyncRun)
    result = await db.execute(statement)
    return result.scalar_one()


async def get_sync_run_id_async(
    db: AsyncSession,
    sync_run_id: UUID,
) -> SyncRun | None:
    statement = select(SyncRun).where(SyncRun.id == sync_run_id)
    result = await db.execute(statement)
    return result.scalar_one_or_none()


async def create_sync_run_async(
    db: AsyncSession,
    source: str,
) -> SyncRun:
    sync_run = SyncRun(source=source, status="running")
    db.add(sync_run)
    await db.flush()
    return sync_run


def mark_sync_run_success_async(
    sync_run: SyncRun,
    added_count: int,
    updated_count: int,
) -> SyncRun:
    sync_run.status = "success"
    sync_run.added_count = added_count
    sync_run.updated_count = updated_count
    sync_run.finished_at = datetime.now(timezone.utc)
    return sync_run


def mark_sync_run_failed_async(sync_run: SyncRun) -> SyncRun:
    sync_run.status = "failed"
    sync_run.finished_at = datetime.now(timezone.utc)
    return sync_run
