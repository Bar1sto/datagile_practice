from app.normalizers.nvd import normalize_nvd


def make_fake_nvd_item(version_data):
    fake_item = {
        "cve": {
            "id": "CVE-TEST-0001",
            "sourceIdentifier": "test@example.com",
            "published": "2026-07-01T00:00:00.000Z",
            "lastModified": "2026-07-01T00:00:00.000Z",
            "vulnStatus": "Received",
            "descriptions": [{"lang": "en", "value": "Test description"}],
            "metrics": {},
            "affected": [
                {
                    "source": "test@example.com",
                    "affectedData": [
                        {
                            "vendor": "Dell",
                            "product": "PowerProtect Data Domain",
                            "versions": [version_data],
                        }
                    ],
                }
            ],
        }
    }
    return fake_item


def test_nvd_normalizer_extracts_affected_products():
    fake_item = make_fake_nvd_item(
        {"version": "0", "lessThan": "2.0.0", "status": "affected"}
    )
    result = normalize_nvd(fake_item)
    assert result["cve_id"] == "CVE-TEST-0001"
    assert result["affected_products"][0]["vendor"] == "Dell"
    assert result["affected_products"][0]["product"] == "PowerProtect Data Domain"
    assert result["affected_products"][0]["version"] == "< 2.0.0"
    assert result["affected_products"][0]["cpe_uri"] is None


def test_nvd_normalizer_formats_less_than_or_equal_version():
    fake_item = make_fake_nvd_item(
        {"version": "0", "lessThanOrEqual": "8.8.0.0 or later", "status": "affected"}
    )
    result = normalize_nvd(fake_item)
    assert result["affected_products"][0]["version"] == "<= 8.8.0.0 or later"


def test_nvd_normalizer_uses_raw_version():
    fake_item = make_fake_nvd_item(
        {
            "version": "1.2.3",
            "status": "affected",
        }
    )
    result = normalize_nvd(fake_item)
    assert result["affected_products"][0]["version"] == "1.2.3"


def test_nvd_normalizer_extract_status():
    fake_item = make_fake_nvd_item(
        {
            "version": "1.2.3",
            "status": "unaffected",
        }
    )
    result = normalize_nvd(fake_item)
    assert result["affected_products"] == []
