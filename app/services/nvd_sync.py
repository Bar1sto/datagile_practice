from datetime import datetime, timedelta, timezone
from dataclasses import dataclass
from sqlalchemy.orm import Session
from app.clients.nvd import NvdClient
from app.normalizers.nvd import normalize_nvd
from app.repositories.cve import upsert_cve
from app.repositories.sync import (
    create_sync_run,
    mark_sync_run_success,
    mark_sync_run_failed,
    get_sync_run_id,
)


@dataclass
class NvdSyncResult:
    total_count: int
    added_count: int
    updated_count: int


class NvdSyncService:
    def __init__(
        self, client: NvdClient, initial_load_months: int = 12, chunk_days: int = 7
    ):
        self.client = client
        self.initial_load_months = initial_load_months
        self.chunk_days = chunk_days

    def _process_vulnerabilities(self, db: Session, vulnerabilities) -> tuple[int, int]:
        added_count = 0
        updated_count = 0
        for item in vulnerabilities:
            normalized = normalize_nvd(item)
            result = upsert_cve(cve_data=normalized, db=db)

            if result.created:
                added_count += 1
            else:
                updated_count += 1
        return added_count, updated_count

    def sync_period(
        self, db: Session, start_date: datetime, end_date: datetime
    ) -> NvdSyncResult:
        sync_run = create_sync_run(db=db, source="NVD")
        db.flush()
        sync_run_id = sync_run.id
        db.commit()
        try:
            vulnerabilities = self.client.fetch_vulnerabilities(
                start_date=start_date, end_date=end_date
            )

            added_count, updated_count = self._process_vulnerabilities(
                db=db, vulnerabilities=vulnerabilities
            )
            success_sync_run = get_sync_run_id(db=db, sync_run_id=sync_run_id)
            if success_sync_run is not None:
                mark_sync_run_success(
                    sync_run=success_sync_run,
                    added_count=added_count,
                    updated_count=updated_count,
                )
            db.commit()
            return NvdSyncResult(
                total_count=len(vulnerabilities),
                added_count=added_count,
                updated_count=updated_count,
            )
        except Exception:
            db.rollback()
            fresh_sync_run = get_sync_run_id(db=db, sync_run_id=sync_run_id)
            if fresh_sync_run is not None:
                mark_sync_run_failed(sync_run=fresh_sync_run)
                db.commit()
            raise

    def sync_initial_load(
        self, db: Session, months: int | None = None
    ) -> NvdSyncResult:
        sync_run = create_sync_run(db=db, source="NVD")
        db.flush()
        sync_run_id = sync_run.id
        db.commit()
        try:
            end_date = datetime.now(timezone.utc)
            if months is not None:
                start_date = end_date - timedelta(days=months * 30)
            else:
                start_date = end_date - timedelta(days=self.initial_load_months * 30)

            chunks_days = _build_date_chunks(
                start_date=start_date, end_date=end_date, chunks_days=self.chunk_days
            )
            total_count = 0
            added_count = 0
            updated_count = 0
            for chunk_start, chunk_end in chunks_days:
                vulnerabilities = self.client.fetch_vulnerabilities(
                    start_date=chunk_start, end_date=chunk_end
                )
                chunk_added, chunk_updated = self._process_vulnerabilities(
                    db=db, vulnerabilities=vulnerabilities
                )
                total_count += len(vulnerabilities)
                added_count += chunk_added
                updated_count += chunk_updated
            success_sync_run = get_sync_run_id(db=db, sync_run_id=sync_run_id)
            if success_sync_run is not None:
                mark_sync_run_success(
                    sync_run=success_sync_run,
                    added_count=added_count,
                    updated_count=updated_count,
                )
            db.commit()
            return NvdSyncResult(
                total_count=total_count,
                added_count=added_count,
                updated_count=updated_count,
            )
        except Exception:
            db.rollback()
            fresh_sync_run = get_sync_run_id(db=db, sync_run_id=sync_run_id)
            if fresh_sync_run is not None:
                mark_sync_run_failed(sync_run=fresh_sync_run)
                db.commit()
            raise

    def sync_recent(self, db: Session, days: int = 1) -> NvdSyncResult:
        end_date = datetime.now(timezone.utc)
        start_date = end_date - timedelta(days=days)
        result = self.sync_period(db=db, start_date=start_date, end_date=end_date)
        return result


def _build_date_chunks(
    start_date: datetime, end_date: datetime, chunks_days: int
) -> list[tuple[datetime, datetime]]:
    result = []
    current_start = start_date
    while current_start < end_date:
        current_end = current_start + timedelta(days=chunks_days)
        if current_end > end_date:
            current_end = end_date
        result.append((current_start, current_end))
        current_start = current_end
    return result
