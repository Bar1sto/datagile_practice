from datetime import datetime, timezone
from decimal import Decimal

import pytest

from app.repositories.cve import upsert_cve_async
from app.repositories.stats import (
    count_all_cves_async,
    get_cve_date_stats_async,
    count_cves_severity_async,
)


@pytest.mark.asyncio
async def test_stats_repository_counts_total_cves(db_session):
    await upsert_cve_async(
        db=db_session,
        cve_data={
            "cve_id": "CVE-2026-STATS-0001",
            "source_identifier": "NVD",
            "published_at": datetime(2026, 7, 1, 12, 0, 0, tzinfo=timezone.utc),
            "last_modified_at": datetime(2026, 7, 2, 12, 0, 0, tzinfo=timezone.utc),
            "vuln_status": "Received",
            "description": "Stats vulnerability 1",
            "cvss_base_score": Decimal("7.0"),
            "cvss_base_severity": "HIGH",
            "cvss_vector": "CVSS:3.1/STATS1",
            "affected_products": [],
        },
    )
    await upsert_cve_async(
        db=db_session,
        cve_data={
            "cve_id": "CVE-2026-STATS-0002",
            "source_identifier": "NVD",
            "published_at": datetime(2026, 7, 3, 12, 0, 0, tzinfo=timezone.utc),
            "last_modified_at": datetime(2026, 7, 4, 12, 0, 0, tzinfo=timezone.utc),
            "vuln_status": "Received",
            "description": "Stats vulnerability 2",
            "cvss_base_score": Decimal("5.0"),
            "cvss_base_severity": "MEDIUM",
            "cvss_vector": "CVSS:3.1/STATS2",
            "affected_products": [],
        },
    )
    await db_session.flush()

    total = await count_all_cves_async(db=db_session)

    assert total >= 2


@pytest.mark.asyncio
async def test_stats_repository_counts_cves_by_severity(db_session):
    await upsert_cve_async(
        db=db_session,
        cve_data={
            "cve_id": "CVE-2026-STATS-0003",
            "source_identifier": "NVD",
            "published_at": datetime(2026, 7, 5, 12, 0, 0, tzinfo=timezone.utc),
            "last_modified_at": datetime(2026, 7, 5, 12, 0, 0, tzinfo=timezone.utc),
            "vuln_status": "Received",
            "description": "Critical stats vulnerability",
            "cvss_base_score": Decimal("9.8"),
            "cvss_base_severity": "CRITICAL",
            "cvss_vector": "CVSS:3.1/STATS3",
            "affected_products": [],
        },
    )
    await db_session.flush()

    by_severity = await count_cves_severity_async(db=db_session)

    assert by_severity["CRITICAL"] >= 1


@pytest.mark.asyncio
async def test_stats_repository_returns_latest_dates(db_session):
    published_at = datetime(2026, 8, 1, 12, 0, 0, tzinfo=timezone.utc)
    last_modified_at = datetime(2026, 8, 2, 12, 0, 0, tzinfo=timezone.utc)

    await upsert_cve_async(
        db=db_session,
        cve_data={
            "cve_id": "CVE-2026-STATS-0004",
            "source_identifier": "NVD",
            "published_at": published_at,
            "last_modified_at": last_modified_at,
            "vuln_status": "Received",
            "description": "Latest date stats vulnerability",
            "cvss_base_score": Decimal("6.0"),
            "cvss_base_severity": "MEDIUM",
            "cvss_vector": "CVSS:3.1/STATS4",
            "affected_products": [],
        },
    )
    await db_session.flush()

    latest_published_at, latest_modified_at = await get_cve_date_stats_async(
        db=db_session
    )

    assert latest_published_at >= published_at
    assert latest_modified_at >= last_modified_at
