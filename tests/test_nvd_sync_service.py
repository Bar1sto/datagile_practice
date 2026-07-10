from datetime import datetime, timezone

import pytest

from app.repositories.cve import get_by_cve_id_async
from app.repositories.sync import list_sync_runs_async
from app.services.nvd_sync import AsyncNvdSyncService


class FakeNvdClient:
    async def fetch_vulnerabilities(
        self,
        start_date: datetime,
        end_date: datetime,
    ) -> list[dict]:
        return [
            {
                "cve": {
                    "id": "CVE-2026-NVD-0001",
                    "sourceIdentifier": "nvd@test.local",
                    "published": "2026-07-01T12:00:00.000",
                    "lastModified": "2026-07-02T12:00:00.000",
                    "vulnStatus": "Analyzed",
                    "descriptions": [
                        {
                            "lang": "en",
                            "value": "Test NVD vulnerability",
                        }
                    ],
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "cvssData": {
                                    "baseScore": 9.8,
                                    "baseSeverity": "CRITICAL",
                                    "vectorString": "CVSS:3.1/TEST",
                                }
                            }
                        ]
                    },
                    "affected": [
                        {
                            "affectedData": [
                                {
                                    "vendor": "TestVendor",
                                    "product": "TestProduct",
                                    "versions": [
                                        {
                                            "version": "1.0",
                                            "status": "affected",
                                        }
                                    ],
                                }
                            ]
                        }
                    ],
                }
            }
        ]


@pytest.mark.asyncio
async def test_nvd_sync_service_saves_vulnerabilities_and_sync_run(db_session):
    service = AsyncNvdSyncService(FakeNvdClient())

    result = await service.sync_period(
        db=db_session,
        start_date=datetime(2026, 7, 1, tzinfo=timezone.utc),
        end_date=datetime(2026, 7, 2, tzinfo=timezone.utc),
    )

    saved = await get_by_cve_id_async(
        db=db_session,
        cve_id="CVE-2026-NVD-0001",
    )
    sync_runs = await list_sync_runs_async(
        db=db_session,
        limit=10,
        offset=0,
    )

    assert result.total_count == 1
    assert result.added_count == 1
    assert result.updated_count == 0

    assert saved is not None
    assert saved.cve_id == "CVE-2026-NVD-0001"
    assert saved.source_identifier == "nvd@test.local"
    assert saved.description == "Test NVD vulnerability"
    assert saved.cvss_base_severity == "CRITICAL"

    assert len(saved.affected_products) == 1
    assert saved.affected_products[0].vendor == "TestVendor"
    assert saved.affected_products[0].product == "TestProduct"

    assert len(sync_runs) >= 1
    assert sync_runs[0].source == "NVD"
    assert sync_runs[0].status == "success"


@pytest.mark.asyncio
async def test_nvd_sync_service_repeated_sync_updates_existing_cve(db_session):
    service = AsyncNvdSyncService(FakeNvdClient())

    first_result = await service.sync_period(
        db=db_session,
        start_date=datetime(2026, 7, 1, tzinfo=timezone.utc),
        end_date=datetime(2026, 7, 2, tzinfo=timezone.utc),
    )
    second_result = await service.sync_period(
        db=db_session,
        start_date=datetime(2026, 7, 1, tzinfo=timezone.utc),
        end_date=datetime(2026, 7, 2, tzinfo=timezone.utc),
    )

    assert first_result.total_count == 1
    assert second_result.total_count == 1

    assert second_result.added_count == 0
    assert second_result.updated_count == 1
