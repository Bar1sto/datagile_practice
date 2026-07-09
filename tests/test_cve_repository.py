from datetime import datetime, timezone
from decimal import Decimal

import pytest

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
