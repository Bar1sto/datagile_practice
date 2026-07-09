from datetime import datetime, timedelta, timezone
from dataclasses import dataclass
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.clients.nvd import AsyncNvdClient
from app.normalizers.nvd import normalize_nvd
from app.repositories.cve import upsert_cve_async
from app.repositories.sync import (
    create_sync_run_async,
    get_sync_run_id_async,
    mark_sync_run_failed_async,
    mark_sync_run_success_async,
)


@dataclass
class AsyncNvdSyncResult:
    total_count: int
    added_count: int
    updated_count: int


class AsyncNvdSyncService:
    def __init__(
        self,
        client: AsyncNvdClient,
        initial_load_months: int = 12,
        chunk_days: int = 7,
    ) -> None:
        self.client = client
        self.initial_load_months = initial_load_months
        self.chunk_days = chunk_days

    async def _process_vulnerabilities(
        self,
        db: AsyncSession,
        vulnerabilities: list[dict[str, Any]],
    ) -> tuple[int, int]:
        added_count = 0
        updated_count = 0
        for item in vulnerabilities:
            normalized = normalize_nvd(item)
            result = await upsert_cve_async(db=db, cve_data=normalized)
            if result.created:
                added_count += 1
            else:
                updated_count += 1
        return added_count, updated_count

    async def sync_period(
        self,
        db: AsyncSession,
        start_date: datetime,
        end_date: datetime,
    ) -> AsyncNvdSyncResult:
        sync_run = await create_sync_run_async(
            db=db,
            source="NVD",
        )
        sync_run_id = sync_run.id
        await db.commit()

        try:
            vulnerabilities = await self.client.fetch_vulnerabilities(
                start_date=start_date,
                end_date=end_date,
            )

            added_count, updated_count = await self._process_vulnerabilities(
                db=db,
                vulnerabilities=vulnerabilities,
            )

            success_sync_run = await get_sync_run_id_async(
                db=db,
                sync_run_id=sync_run_id,
            )

            if success_sync_run is not None:
                mark_sync_run_success_async(
                    sync_run=success_sync_run,
                    added_count=added_count,
                    updated_count=updated_count,
                )
                await db.commit()
            return AsyncNvdSyncResult(
                total_count=len(vulnerabilities),
                added_count=added_count,
                updated_count=updated_count,
            )
        except Exception:
            await db.rollback()
            failed_sync_run = await get_sync_run_id_async(
                db=db,
                sync_run_id=sync_run_id,
            )
            if failed_sync_run is not None:
                mark_sync_run_failed_async(
                    sync_run=failed_sync_run,
                )
                await db.commit()
            raise

    async def sync_initial_load(
        self, db: AsyncSession, months: int | None = None
    ) -> AsyncNvdSyncResult:
        sync_run = await create_sync_run_async(
            db=db,
            source="NVD",
        )
        sync_run_id = sync_run.id
        await db.commit()
        try:
            end_date = datetime.now(timezone.utc)
            if months is not None:
                start_date = end_date - timedelta(days=months * 30)
            else:
                start_date = end_date - timedelta(days=self.initial_load_months * 30)
            chunks = _build_date_chunks(
                start_date=start_date,
                end_date=end_date,
                chunk_days=self.chunk_days,
            )

            total_count = 0
            added_count = 0
            updated_count = 0

            for chunk_start, chunk_end in chunks:
                vulnerabilities = await self.client.fetch_vulnerabilities(
                    start_date=chunk_start,
                    end_date=chunk_end,
                )
                chunk_added, chunk_updated = await self._process_vulnerabilities(
                    db=db,
                    vulnerabilities=vulnerabilities,
                )
                total_count += len(vulnerabilities)
                added_count += chunk_added
                updated_count += chunk_updated
            success_sync_run = await get_sync_run_id_async(
                db=db,
                sync_run_id=sync_run_id,
            )
            if success_sync_run is not None:
                mark_sync_run_success_async(
                    sync_run=success_sync_run,
                    added_count=added_count,
                    updated_count=updated_count,
                )
                await db.commit()
            return AsyncNvdSyncResult(
                total_count=total_count,
                added_count=added_count,
                updated_count=updated_count,
            )
        except Exception:
            await db.rollback()
            failed_sync_run = await get_sync_run_id_async(
                db=db,
                sync_run_id=sync_run_id,
            )
            if failed_sync_run is not None:
                mark_sync_run_failed_async(
                    sync_run=failed_sync_run,
                )
                await db.commit()
            raise

    async def sync_recent(
        self,
        db: AsyncSession,
        days: int = 1,
    ) -> AsyncNvdSyncResult:
        end_date = datetime.now(timezone.utc)
        start_date = end_date - timedelta(days=days)
        return await self.sync_period(
            db=db,
            start_date=start_date,
            end_date=end_date,
        )


def _build_date_chunks(
    start_date: datetime,
    end_date: datetime,
    chunk_days: int,
) -> list[tuple[datetime, datetime]]:
    result = []
    current_start = start_date
    while current_start < end_date:
        current_end = current_start + timedelta(days=chunk_days)
        if current_end > end_date:
            current_end = end_date
        result.append((current_start, current_end))
        current_start = current_end
    return result
