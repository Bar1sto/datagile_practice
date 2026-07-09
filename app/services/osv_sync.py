from dataclasses import dataclass
from sqlalchemy.ext.asyncio import AsyncSession
from app.clients.osv import OsvClient
from app.normalizers.osv import normalize_osv

from app.repositories.cve import upsert_cve_async
from app.repositories.sync import (
    create_sync_run_async,
    get_sync_run_id_async,
    mark_sync_run_failed_async,
    mark_sync_run_success_async,
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
        db: AsyncSession,
        ecosystem: str,
        package_name: str,
        version: str,
    ) -> OsvSyncResult:
        sync_run = await create_sync_run_async(
            db=db,
            source="OSV",
        )
        sync_run_id = sync_run.id
        await db.commit()
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
                result = await upsert_cve_async(db=db, cve_data=normalized)
                if result.created:
                    added_count += 1
                else:
                    updated_count += 1
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
            return OsvSyncResult(
                total_count=total_count,
                added_count=added_count,
                updated_count=updated_count,
                skipped_count=skipped_count,
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
