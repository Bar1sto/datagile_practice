from datetime import datetime
from typing import Any
from decimal import Decimal


def _get_en_description(descriptions: list[dict[str, Any]]) -> str | None:
    for desc in descriptions:
        if desc.get("lang") == "en":
            return desc.get("value")
    return None


def _parse_nvd_datetime(value: Any) -> datetime:
    if not isinstance(value, str):
        raise TypeError(value)
    if value.endswith("Z"):
        value = value.replace("Z", "+00:00")
    return datetime.fromisoformat(value)


def _empty_cvss() -> dict[str, Any]:
    return {
        "cvss_base_score": None,
        "cvss_base_severity": None,
        "cvss_vector": None,
    }


def _extract_cvss_v31(metrics: dict[str, Any]) -> dict[str, Any]:
    v31_metrics = metrics.get("cvssMetricV31")
    if not v31_metrics:
        return _empty_cvss()

    metric = v31_metrics[0]
    cvss_data = metric.get("cvssData")
    if not isinstance(cvss_data, dict):
        return _empty_cvss()
    cvss_base_score = cvss_data.get("baseScore")
    if cvss_base_score is not None:
        cvss_base_score = Decimal(str(cvss_base_score))
    cvss_base_severity = cvss_data.get("baseSeverity")
    cvss_vector = cvss_data.get("vectorString")
    return {
        "cvss_base_score": cvss_base_score,
        "cvss_base_severity": cvss_base_severity,
        "cvss_vector": cvss_vector,
    }


def _extract_cvss_v30(metrics: dict[str, Any]) -> dict[str, Any]:
    v30_metrics = metrics.get("cvssMetricV30")
    if not v30_metrics:
        return _empty_cvss()
    metric = v30_metrics[0]
    cvss_data = metric.get("cvssData")
    if not isinstance(cvss_data, dict):
        return _empty_cvss()
    cvss_base_score = cvss_data.get("baseScore")
    if cvss_base_score is not None:
        cvss_base_score = Decimal(str(cvss_base_score))
    cvss_base_severity = cvss_data.get("baseSeverity")
    cvss_vector = cvss_data.get("vectorString")
    return {
        "cvss_base_score": cvss_base_score,
        "cvss_base_severity": cvss_base_severity,
        "cvss_vector": cvss_vector,
    }


def _extract_cvss_v2(metrics: dict[str, Any]) -> dict[str, Any]:
    v2_metrics = metrics.get("cvssMetricV2")
    if not v2_metrics:
        return _empty_cvss()

    metric = v2_metrics[0]
    cvss_data = metric.get("cvssData")
    if not isinstance(cvss_data, dict):
        return _empty_cvss()
    cvss_base_score = cvss_data.get("baseScore")
    if cvss_base_score is not None:
        cvss_base_score = Decimal(str(cvss_base_score))
    cvss_base_severity = metric.get("baseSeverity")
    cvss_vector = cvss_data.get("vectorString")
    return {
        "cvss_base_score": cvss_base_score,
        "cvss_base_severity": cvss_base_severity,
        "cvss_vector": cvss_vector,
    }


def _controller_extract_cvss(metrics: dict[str, Any]) -> dict[str, Any]:
    if metrics.get("cvssMetricV31"):
        return _extract_cvss_v31(metrics)
    if metrics.get("cvssMetricV30"):
        return _extract_cvss_v30(metrics)
    if metrics.get("cvssMetricV2"):
        return _extract_cvss_v2(metrics)
    return _empty_cvss()


def normalize_nvd(
    item: dict[str, Any],
) -> dict[str, Any]:
    cve = item.get("cve")
    if not isinstance(cve, dict):
        raise TypeError("NVD item does not contain valid cve object")
    metrics = cve.get("metrics") or {}
    cvss_data = _controller_extract_cvss(metrics)
    response_cve = {
        "cve_id": cve["id"],
        "source_identifier": cve.get("sourceIdentifier"),
        "published_at": _parse_nvd_datetime(cve["published"]),
        "last_modified_at": _parse_nvd_datetime(cve["lastModified"]),
        "vuln_status": cve.get("vulnStatus"),
        "description": _get_en_description(cve.get("descriptions") or []),
        "cvss_base_score": cvss_data["cvss_base_score"],
        "cvss_base_severity": cvss_data["cvss_base_severity"],
        "cvss_vector": cvss_data["cvss_vector"],
    }
    return response_cve
