from datetime import datetime
from typing import Any
from decimal import Decimal


class NvdNormalizer:
    def normalize(
        self,
        item: dict[str, Any],
    ) -> dict[str, Any]:
        cve = item.get("cve")
        if not isinstance(cve, dict):
            raise TypeError("NVD item does not contain valid cve object")
        metrics = cve.get("metrics") or {}
        cvss_data = self._extract_cvss(metrics)
        response_cve = {
            "cve_id": cve["id"],
            "source_identifier": cve.get("sourceIdentifier"),
            "published_at": self._parse_nvd_datetime(cve["published"]),
            "last_modified_at": self._parse_nvd_datetime(cve["lastModified"]),
            "vuln_status": cve.get("vulnStatus"),
            "description": self._get_en_description(cve.get("descriptions") or []),
            "cvss_base_score": cvss_data["cvss_base_score"],
            "cvss_base_severity": cvss_data["cvss_base_severity"],
            "cvss_vector": cvss_data["cvss_vector"],
            "affected_products": self._extract_affected_products(cve),
        }
        return response_cve

    def _get_en_description(self, descriptions: list[dict[str, Any]]) -> str | None:
        for desc in descriptions:
            if desc.get("lang") == "en":
                return desc.get("value")
        return None

    def _parse_nvd_datetime(self, value: Any) -> datetime:
        if not isinstance(value, str):
            raise TypeError(value)
        if value.endswith("Z"):
            value = value.replace("Z", "+00:00")
        return datetime.fromisoformat(value)

    def _empty_cvss(self) -> dict[str, Any]:
        return {
            "cvss_base_score": None,
            "cvss_base_severity": None,
            "cvss_vector": None,
        }

    def _extract_cvss_v31(self, metrics: dict[str, Any]) -> dict[str, Any]:
        v31_metrics = metrics.get("cvssMetricV31")
        if not v31_metrics:
            return self._empty_cvss()

        metric = v31_metrics[0]
        cvss_data = metric.get("cvssData")
        if not isinstance(cvss_data, dict):
            return self._empty_cvss()
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

    def _extract_cvss_v30(self, metrics: dict[str, Any]) -> dict[str, Any]:
        v30_metrics = metrics.get("cvssMetricV30")
        if not v30_metrics:
            return self._empty_cvss()
        metric = v30_metrics[0]
        cvss_data = metric.get("cvssData")
        if not isinstance(cvss_data, dict):
            return self._empty_cvss()
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

    def _extract_cvss_v2(self, metrics: dict[str, Any]) -> dict[str, Any]:
        v2_metrics = metrics.get("cvssMetricV2")
        if not v2_metrics:
            return self._empty_cvss()

        metric = v2_metrics[0]
        cvss_data = metric.get("cvssData")
        if not isinstance(cvss_data, dict):
            return self._empty_cvss()
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

    def _extract_cvss(self, metrics: dict[str, Any]) -> dict[str, Any]:
        if metrics.get("cvssMetricV31"):
            return self._extract_cvss_v31(metrics)
        if metrics.get("cvssMetricV30"):
            return self._extract_cvss_v30(metrics)
        if metrics.get("cvssMetricV2"):
            return self._extract_cvss_v2(metrics)
        return self._empty_cvss()

    def _extract_affected_products(self, cve: dict[str, Any]) -> list[dict[str, Any]]:
        result = []
        affected_items = cve.get("affected") or []
        for affected_item in affected_items:
            affected_data_list = affected_item.get("affectedData") or []
            for affected_data in affected_data_list:
                vendor = affected_data.get("vendor")
                product = affected_data.get("product")
                versions = affected_data.get("versions") or []
                if vendor is None or product is None:
                    continue
                if not versions:
                    result.append(
                        {
                            "vendor": vendor,
                            "product": product,
                            "version": None,
                            "cpe_uri": None,
                        }
                    )
                    continue
                for version_data in versions:
                    if not isinstance(version_data, dict):
                        continue
                    status = version_data.get("status")
                    if status is not None and status != "affected":
                        continue
                    less_than = version_data.get("lessThan")
                    less_than_or_equal = version_data.get("lessThanOrEqual")
                    raw_version = version_data.get("version")
                    if less_than is not None:
                        version_value = "< " + less_than
                    elif less_than_or_equal is not None:
                        version_value = "<= " + less_than_or_equal
                    else:
                        version_value = raw_version
                    result.append(
                        {
                            "vendor": vendor,
                            "product": product,
                            "version": version_value,
                            "cpe_uri": None,
                        }
                    )
        return result

    def _extract_affected_products_from_node(self, node: Any) -> list[dict[str, Any]]:
        result = []
        if not isinstance(node, dict):
            return []
        match = node.get("cpeMatch")
        for item in match or []:
            if not isinstance(item, dict):
                continue
            criteria = item.get("criteria")
            criteria_parse = self._parse_cpe(criteria)
            if criteria_parse is not None:
                result.append(criteria_parse)
        children = node.get("children")
        for child in children or []:
            child_result = self._extract_affected_products_from_node(child)
            result.extend(child_result)
        return result

    def _parse_cpe(self, criteria: Any) -> dict[str, Any] | None:
        if not isinstance(criteria, str):
            return None
        parts = criteria.split(":")
        result = {}
        if len(parts) < 6:
            return None
        vendor = parts[3]
        product = parts[4]
        version = parts[5]
        if version == "*" or version == "-":
            version = None
        result["vendor"] = vendor
        result["product"] = product
        result["version"] = version
        result["cpe_uri"] = criteria
        return result


def normalize_nvd(
    item: dict[str, Any],
) -> dict[str, Any]:
    nvd_normalizer = NvdNormalizer()
    result = nvd_normalizer.normalize(item)
    return result
