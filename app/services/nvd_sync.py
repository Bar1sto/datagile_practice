from datetime import datetime
from dataclasses import dataclass
from sqlalchemy.orm import Session
from app.clients.nvd import NvdClient
from app.normalizers.nvd import normalize_nvd
from app.repositories.cve import upsert_cve
from app.repositories.sync import create_sync_run, mark_sync_run_success


@dataclass
class NvdSyncResult:
    total_count: int
    added_count: int
    updated_count: int


class NvdSyncService:
    def __init__(self, client: NvdClient):
        self.client = client

    def sync_period(
        self, db: Session, start_date: datetime, end_date: datetime
    ) -> NvdSyncResult:
        sync_run = create_sync_run(db=db, source="NVD")
        vulnerabilities = self.client.fetch_vulnerabilities(
            start_date=start_date, end_date=end_date
        )
        added_count = 0
        updated_count = 0
        for item in vulnerabilities:
            normalized = normalize_nvd(item)
            result = upsert_cve(cve_data=normalized, db=db)

            if result.created:
                added_count += 1
            else:
                updated_count += 1
        mark_sync_run_success(
            sync_run=sync_run,
            added_count=added_count,
            updated_count=updated_count,
        )
        return NvdSyncResult(
            total_count=len(vulnerabilities),
            added_count=added_count,
            updated_count=updated_count,
        )
