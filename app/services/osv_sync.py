from dataclasses import dataclass
from sqlalchemy.orm import Session
from app.clients.osv import OsvClient
from app.normalizers.osv import normalize_osv
from app.repositories.cve import upsert_cve
from app.repositories.sync import (
    create_sync_run,
    get_sync_run_id,
    mark_sync_run_failed,
    mark_sync_run_success,
)


@dataclass
class OsvSyncResult:
    total_count: int
    added_count: int
    updated_count: int
    skipped_count: int


class OsvSyncService:
    def __init__(self, client: OsvClient) -> None:
        self.client = client

    async def sync_package(
        self,
        db: Session,
        ecosystem: str,
        package_name: str,
        version: str,
    ) -> OsvSyncResult:
        sync_run = create_sync_run(
            db=db,
            source="OSV",
        )
        db.flush()
        sync_run_id = sync_run.id
        db.commit()
        try:
            vulns = await self.client.query_package(
                package_name=package_name, version=version, ecosystem=ecosystem
            )
            total_count = len(vulns)
            added_count = 0
            updated_count = 0
            skipped_count = 0
            seen_cve_ids: set[str] = set()
            for item in vulns:
                normalized = normalize_osv(item)
                if normalized is None:
                    skipped_count += 1
                    continue
                cve_id = normalized["cve_id"]
                if cve_id in seen_cve_ids:
                    skipped_count += 1
                    continue
                seen_cve_ids.add(cve_id)
                result = upsert_cve(db=db, cve_data=normalized)
                if result.created:
                    added_count += 1
                else:
                    updated_count += 1
            success_sync_run = get_sync_run_id(
                db=db,
                sync_run_id=sync_run_id,
            )
            if success_sync_run is not None:
                mark_sync_run_success(
                    sync_run=success_sync_run,
                    added_count=added_count,
                    updated_count=updated_count,
                )
                db.commit()
            return OsvSyncResult(
                total_count=total_count,
                added_count=added_count,
                updated_count=updated_count,
                skipped_count=skipped_count,
            )
        except Exception:
            db.rollback()
            failed_sync_run = get_sync_run_id(
                db=db,
                sync_run_id=sync_run_id,
            )
            if failed_sync_run is not None:
                mark_sync_run_failed(
                    sync_run=failed_sync_run,
                )
                db.commit()
            raise
