from datetime import datetime, timezone
from decimal import Decimal

import pytest
from app.repositories.cve import list_cves_async, count_cves_async
from app.repositories.cve import upsert_cve_async


@pytest.mark.asyncio
async def test_cve_repository_upsert_cve(db_session):
    fake_data = {
        "cve_id": "CVE-2026-53478",
        "source_identifier": "security_alert@emc.com",
        "published_at": datetime(2026, 7, 3, 12, 16, 32, tzinfo=timezone.utc),
        "last_modified_at": datetime(2026, 7, 3, 12, 16, 32, tzinfo=timezone.utc),
        "vuln_status": "Received",
        "description": "Dell PowerProtect Data Domain, versions 7.7.1.0 through 8.7, LTS2026 release version 8.6.1.0 through 8.6.1.10, LTS2025 release version 8.3.1.0 through 8.3.1.30, LTS2024 release versions 7.13.1.0 through 7.13.1.70 contain an improper neutralization of special elements used in an OS command ('OS command Injection') vulnerability. A high privileged attacker with remote access could potentially exploit this vulnerability, leading to command execution.",
        "cvss_base_score": Decimal("7.20"),
        "cvss_base_severity": "HIGH",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H",
        "affected_products": [
            {
                "vendor": "Dell",
                "product": "PowerProtect Data Domain",
                "version": "< 8.0.0",
                "cpe_uri": None,
            },
        ],
    }

    result = await upsert_cve_async(db=db_session, cve_data=fake_data)
    await db_session.flush()

    affected = result.record.affected_products[0]

    assert result.created is True
    assert result.record.cve_id == "CVE-2026-53478"
    assert len(result.record.affected_products) == 1
    assert affected.vendor == "Dell"
    assert affected.product == "PowerProtect Data Domain"
    assert affected.version == "< 8.0.0"


@pytest.mark.asyncio
async def test_cve_repository_upsert_existing_cve_updates_record(db_session):
    fake_data = {
        "cve_id": "CVE-2026-60001",
        "source_identifier": "NVD",
        "published_at": datetime(2026, 7, 3, 12, 16, 32, tzinfo=timezone.utc),
        "last_modified_at": datetime(2026, 7, 3, 12, 16, 32, tzinfo=timezone.utc),
        "vuln_status": "Received",
        "description": "Initial description",
        "cvss_base_score": Decimal("5.00"),
        "cvss_base_severity": "MEDIUM",
        "cvss_vector": "CVSS:3.1/INITIAL",
        "affected_products": [
            {
                "vendor": "VendorA",
                "product": "ProductA",
                "version": "1.0",
                "cpe_uri": None,
            },
        ],
    }

    first_result = await upsert_cve_async(db=db_session, cve_data=fake_data)
    await db_session.flush()

    updated_data = fake_data.copy()
    updated_data["description"] = "Updated description"
    updated_data["cvss_base_score"] = Decimal("7.50")
    updated_data["cvss_base_severity"] = "HIGH"

    second_result = await upsert_cve_async(db=db_session, cve_data=updated_data)
    await db_session.flush()

    assert first_result.created is True
    assert second_result.created is False
    assert second_result.record.description == "Updated description"
    assert second_result.record.cvss_base_score == Decimal("7.50")
    assert second_result.record.cvss_base_severity == "HIGH"


@pytest.mark.asyncio
async def test_cve_repository_upsert_replaces_affected_products(db_session):
    fake_data = {
        "cve_id": "CVE-2026-60002",
        "source_identifier": "NVD",
        "published_at": datetime(2026, 7, 3, 12, 16, 32, tzinfo=timezone.utc),
        "last_modified_at": datetime(2026, 7, 3, 12, 16, 32, tzinfo=timezone.utc),
        "vuln_status": "Received",
        "description": "Initial description",
        "cvss_base_score": Decimal("5.00"),
        "cvss_base_severity": "MEDIUM",
        "cvss_vector": "CVSS:3.1/INITIAL",
        "affected_products": [
            {
                "vendor": "VendorA",
                "product": "ProductA",
                "version": "1.0",
                "cpe_uri": None,
            },
        ],
    }

    await upsert_cve_async(db=db_session, cve_data=fake_data)
    await db_session.flush()

    updated_data = fake_data.copy()
    updated_data["affected_products"] = [
        {
            "vendor": "VendorB",
            "product": "ProductB",
            "version": "2.0",
            "cpe_uri": None,
        }
    ]

    result = await upsert_cve_async(db=db_session, cve_data=updated_data)
    await db_session.flush()

    assert result.created is False
    assert len(result.record.affected_products) == 1
    assert result.record.affected_products[0].vendor == "VendorB"
    assert result.record.affected_products[0].product == "ProductB"
    assert result.record.affected_products[0].version == "2.0"


@pytest.mark.asyncio
async def test_cve_repository_filters_by_vendor_and_product(db_session):
    dell_data = {
        "cve_id": "CVE-2026-70001",
        "source_identifier": "NVD",
        "published_at": datetime(2026, 7, 1, 12, 0, 0, tzinfo=timezone.utc),
        "last_modified_at": datetime(2026, 7, 1, 12, 0, 0, tzinfo=timezone.utc),
        "vuln_status": "Received",
        "description": "Dell vulnerability",
        "cvss_base_score": Decimal("7.20"),
        "cvss_base_severity": "HIGH",
        "cvss_vector": "CVSS:3.1/DELL",
        "affected_products": [
            {
                "vendor": "Dell",
                "product": "PowerProtect",
                "version": "1.0",
                "cpe_uri": None,
            }
        ],
    }
    other_data = {
        "cve_id": "CVE-2026-70002",
        "source_identifier": "NVD",
        "published_at": datetime(2026, 7, 2, 12, 0, 0, tzinfo=timezone.utc),
        "last_modified_at": datetime(2026, 7, 2, 12, 0, 0, tzinfo=timezone.utc),
        "vuln_status": "Received",
        "description": "Other vulnerability",
        "cvss_base_score": Decimal("5.00"),
        "cvss_base_severity": "MEDIUM",
        "cvss_vector": "CVSS:3.1/OTHER",
        "affected_products": [
            {
                "vendor": "Microsoft",
                "product": "Windows",
                "version": "11",
                "cpe_uri": None,
            }
        ],
    }

    await upsert_cve_async(db=db_session, cve_data=dell_data)
    await upsert_cve_async(db=db_session, cve_data=other_data)
    await db_session.flush()

    records = await list_cves_async(
        db=db_session,
        limit=20,
        offset=0,
        severity=None,
        published_from=None,
        published_to=None,
        vendor="Dell",
        product="PowerProtect",
    )
    total = await count_cves_async(
        db=db_session,
        severity=None,
        published_from=None,
        published_to=None,
        vendor="Dell",
        product="PowerProtect",
    )

    assert total == 1
    assert len(records) == 1
    assert records[0].cve_id == "CVE-2026-70001"


@pytest.mark.asyncio
async def test_cve_repository_filters_by_severity_and_date_range(db_session):
    matching_data = {
        "cve_id": "CVE-2026-80001",
        "source_identifier": "NVD",
        "published_at": datetime(2026, 7, 5, 12, 0, 0, tzinfo=timezone.utc),
        "last_modified_at": datetime(2026, 7, 5, 12, 0, 0, tzinfo=timezone.utc),
        "vuln_status": "Received",
        "description": "Matching vulnerability",
        "cvss_base_score": Decimal("9.10"),
        "cvss_base_severity": "CRITICAL",
        "cvss_vector": "CVSS:3.1/MATCH",
        "affected_products": [
            {
                "vendor": "VendorA",
                "product": "ProductA",
                "version": "1.0",
                "cpe_uri": None,
            }
        ],
    }

    wrong_severity_data = {
        "cve_id": "CVE-2026-80002",
        "source_identifier": "NVD",
        "published_at": datetime(2026, 7, 5, 12, 0, 0, tzinfo=timezone.utc),
        "last_modified_at": datetime(2026, 7, 5, 12, 0, 0, tzinfo=timezone.utc),
        "vuln_status": "Received",
        "description": "Wrong severity vulnerability",
        "cvss_base_score": Decimal("5.00"),
        "cvss_base_severity": "MEDIUM",
        "cvss_vector": "CVSS:3.1/WRONGSEVERITY",
        "affected_products": [],
    }

    wrong_date_data = {
        "cve_id": "CVE-2026-80003",
        "source_identifier": "NVD",
        "published_at": datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc),
        "last_modified_at": datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc),
        "vuln_status": "Received",
        "description": "Wrong date vulnerability",
        "cvss_base_score": Decimal("9.50"),
        "cvss_base_severity": "CRITICAL",
        "cvss_vector": "CVSS:3.1/WRONGDATE",
        "affected_products": [],
    }

    await upsert_cve_async(db=db_session, cve_data=matching_data)
    await upsert_cve_async(db=db_session, cve_data=wrong_severity_data)
    await upsert_cve_async(db=db_session, cve_data=wrong_date_data)
    await db_session.flush()

    records = await list_cves_async(
        db=db_session,
        limit=20,
        offset=0,
        severity="CRITICAL",
        published_from=datetime(2026, 7, 1, 0, 0, 0, tzinfo=timezone.utc),
        published_to=datetime(2026, 7, 31, 23, 59, 59, tzinfo=timezone.utc),
        vendor=None,
        product=None,
    )
    total = await count_cves_async(
        db=db_session,
        severity="CRITICAL",
        published_from=datetime(2026, 7, 1, 0, 0, 0, tzinfo=timezone.utc),
        published_to=datetime(2026, 7, 31, 23, 59, 59, tzinfo=timezone.utc),
        vendor=None,
        product=None,
    )

    assert total == 1
    assert len(records) == 1
    assert records[0].cve_id == "CVE-2026-80001"
