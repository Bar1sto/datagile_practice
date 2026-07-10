from app.normalizers.osv import normalize_osv


def test_normalize_osv_with_cve_alias():
    item = {
        "id": "GHSA-test",
        "published": "2026-01-01T00:00:00Z",
        "modified": "2026-01-02T00:00:00Z",
        "aliases": ["GHSA-xxxx", "CVE-2026-12345"],
        "summary": "Short summary",
        "details": "Detailed vulnerability description",
        "affected": [
            {
                "package": {
                    "ecosystem": "PyPI",
                    "name": "jinja2",
                }
            }
        ],
    }

    result = normalize_osv(item)

    assert result is not None
    assert result["cve_id"] == "CVE-2026-12345"
    assert result["source_identifier"] == "OSV"
    assert result["description"] == "Detailed vulnerability description"
    assert result["affected_products"] == [
        {
            "vendor": "PyPI",
            "product": "jinja2",
            "version": None,
            "cpe_uri": None,
        }
    ]


def test_normalize_osv_without_cve_alias_returns_none():
    item = {
        "id": "GHSA-test",
        "aliases": ["GHSA-xxxx"],
        "summary": "Summary",
        "affected": [],
    }
    result = normalize_osv(item)
    assert result is None


def test_normalize_osv_uses_summary_when_details_missing():
    item = {
        "id": "GHSA-test",
        "published": "2026-01-01T00:00:00Z",
        "modified": "2026-01-02T00:00:00Z",
        "aliases": ["CVE-2026-12345"],
        "summary": "Summary fallback",
        "details": "",
        "affected": [],
    }
    result = normalize_osv(item)
    assert result is not None
    assert result["description"] == "Summary fallback"
