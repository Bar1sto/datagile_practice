import pytest

from app.repositories.cve import get_by_cve_id_async
from app.services.osv_sync import OsvSyncService


class FakeOsvClient:
    async def query_package(
        self,
        ecosystem: str,
        package_name: str,
        version: str,
    ) -> list[dict]:
        return [
            {
                "id": "GHSA-test-1",
                "published": "2026-01-01T00:00:00Z",
                "modified": "2026-01-02T00:00:00Z",
                "aliases": ["GHSA-test-1", "CVE-2026-90001"],
                "summary": "Test summary",
                "details": "Test details",
                "affected": [
                    {
                        "package": {
                            "ecosystem": ecosystem,
                            "name": package_name,
                        }
                    }
                ],
            },
            {
                "id": "GHSA-without-cve",
                "published": "2026-01-01T00:00:00Z",
                "modified": "2026-01-02T00:00:00Z",
                "aliases": ["GHSA-without-cve"],
                "summary": "Should be skipped",
                "affected": [],
            },
        ]


class SecondFakeOsvClient:
    async def query_package(
        self,
        ecosystem: str,
        package_name: str,
        version: str,
    ) -> list[dict]:
        return [
            {
                "id": "GHSA-test-2",
                "published": "2026-01-01T00:00:00Z",
                "modified": "2026-01-02T00:00:00Z",
                "aliases": ["GHSA-test-2", "CVE-2026-90002"],
                "summary": "Test summary",
                "details": "Test details",
                "affected": [
                    {
                        "package": {
                            "ecosystem": ecosystem,
                            "name": package_name,
                        }
                    }
                ],
            },
            {
                "id": "GHSA-without-cve-2",
                "published": "2026-01-01T00:00:00Z",
                "modified": "2026-01-02T00:00:00Z",
                "aliases": ["GHSA-without-cve-2"],
                "summary": "Should be skipped",
                "affected": [],
            },
        ]


@pytest.mark.asyncio
async def test_osv_sync_service_saves_only_vulnerabilities_with_cve_alias(db_session):
    service = OsvSyncService(client=FakeOsvClient())

    result = await service.sync_package(
        db=db_session,
        ecosystem="PyPI",
        package_name="jinja2",
        version="2.4.1",
    )

    saved = await get_by_cve_id_async(
        db=db_session,
        cve_id="CVE-2026-90001",
    )

    assert result.total_count == 2
    assert result.added_count == 1
    assert result.updated_count == 0
    assert result.skipped_count == 1

    assert saved is not None
    assert saved.cve_id == "CVE-2026-90001"
    assert saved.source_identifier == "OSV"
    assert saved.description == "Test details"
    assert len(saved.affected_products) == 1
    assert saved.affected_products[0].vendor == "PyPI"
    assert saved.affected_products[0].product == "jinja2"


@pytest.mark.asyncio
async def test_osv_sync_service_repeated_sync_updates_existing_cve(db_session):
    service = OsvSyncService(SecondFakeOsvClient())

    first_result = await service.sync_package(
        db=db_session,
        ecosystem="PyPI",
        package_name="jinja2",
        version="2.4.1",
    )

    second_result = await service.sync_package(
        db=db_session,
        ecosystem="PyPI",
        package_name="jinja2",
        version="2.4.1",
    )

    saved = await get_by_cve_id_async(
        db=db_session,
        cve_id="CVE-2026-90002",
    )

    assert first_result.total_count == 2
    assert first_result.added_count == 1
    assert first_result.updated_count == 0
    assert first_result.skipped_count == 1

    assert second_result.total_count == 2
    assert second_result.added_count == 0
    assert second_result.updated_count == 1
    assert second_result.skipped_count == 1

    assert saved is not None
    assert saved.cve_id == "CVE-2026-90002"
