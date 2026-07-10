from datetime import datetime, timezone
from decimal import Decimal

import pytest
from httpx import ASGITransport, AsyncClient

from app.db.database import get_async_db
from app.main import app
from app.repositories.cve import upsert_cve_async


@pytest.fixture()
def override_db_dependency(db_session):
    async def get_test_db():
        yield db_session

    app.dependency_overrides[get_async_db] = get_test_db
    yield
    app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_get_cves_returns_paginated_list(db_session, override_db_dependency):
    await upsert_cve_async(
        db=db_session,
        cve_data={
            "cve_id": "CVE-2026-API-0001",
            "source_identifier": "NVD",
            "published_at": datetime(2026, 7, 1, 12, 0, 0, tzinfo=timezone.utc),
            "last_modified_at": datetime(2026, 7, 2, 12, 0, 0, tzinfo=timezone.utc),
            "vuln_status": "Analyzed",
            "description": "API test vulnerability",
            "cvss_base_score": Decimal("8.0"),
            "cvss_base_severity": "HIGH",
            "cvss_vector": "CVSS:3.1/API",
            "affected_products": [
                {
                    "vendor": "ApiVendor",
                    "product": "ApiProduct",
                    "version": "1.0",
                    "cpe_uri": None,
                }
            ],
        },
    )
    await db_session.flush()

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        response = await client.get("/cve/", params={"severity": "HIGH"})

    assert response.status_code == 200

    data = response.json()

    assert data["total"] >= 1
    assert data["limit"] == 20
    assert data["offset"] == 0
    assert any(item["cve_id"] == "CVE-2026-API-0001" for item in data["items"])


@pytest.mark.asyncio
async def test_get_cve_by_id_returns_detail(db_session, override_db_dependency):
    await upsert_cve_async(
        db=db_session,
        cve_data={
            "cve_id": "CVE-2026-API-0002",
            "source_identifier": "NVD",
            "published_at": datetime(2026, 7, 1, 12, 0, 0, tzinfo=timezone.utc),
            "last_modified_at": datetime(2026, 7, 2, 12, 0, 0, tzinfo=timezone.utc),
            "vuln_status": "Analyzed",
            "description": "API detail vulnerability",
            "cvss_base_score": Decimal("9.0"),
            "cvss_base_severity": "CRITICAL",
            "cvss_vector": "CVSS:3.1/APIDETAIL",
            "affected_products": [
                {
                    "vendor": "DetailVendor",
                    "product": "DetailProduct",
                    "version": "2.0",
                    "cpe_uri": None,
                }
            ],
        },
    )
    await db_session.flush()

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        response = await client.get("/cve/CVE-2026-API-0002")

    assert response.status_code == 200

    data = response.json()

    assert data["cve_id"] == "CVE-2026-API-0002"
    assert data["cvss_base_severity"] == "CRITICAL"
    assert len(data["affected_products"]) == 1
    assert data["affected_products"][0]["vendor"] == "DetailVendor"


@pytest.mark.asyncio
async def test_get_cve_by_id_returns_unified_error_for_missing_cve(
    override_db_dependency,
):
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        response = await client.get("/cve/CVE-2099-NOT-FOUND")

    assert response.status_code == 404

    data = response.json()

    assert data == {
        "error": {
            "code": "CVE_NOT_FOUND",
            "message": "CVE not found",
        }
    }
