from datetime import datetime
from typing import Any


class OsvNormalizer:
    def normalize(
        self,
        item: dict[str, Any],
    ) -> dict[str, Any] | None:
        cve_id = self._extract_cve_id(item)
        if cve_id is None:
            return None
        return {
            "cve_id": cve_id,
            "source_identifier": "OSV",
            "published_at": self._parse_datetime(item.get("published")),
            "last_modified_at": self._parse_datetime(item.get("modified")),
            "vuln_status": None,
            "description": self._extract_description(item),
            "cvss_base_score": None,
            "cvss_base_severity": None,
            "cvss_vector": self._extract_cvss_vector(item),
            "affected_products": self._extract_affected_products(item),
        }

    def _extract_cve_id(self, item: dict[str, Any]) -> str | None:
        aliases = item.get("aliases", [])
        if not isinstance(aliases, list):
            return None
        for alias in aliases:
            if isinstance(alias, str) and alias.startswith("CVE-"):
                return alias
        return None

    def _parse_datetime(self, value: str | None) -> datetime | None:
        if value is None:
            return None
        return datetime.fromisoformat(value.replace("Z", "+00:00"))

    def _extract_description(self, item: dict[str, Any]) -> str:
        details = item.get("details")
        if isinstance(details, str) and details:
            return details
        summary = item.get("summary")
        if isinstance(summary, str) and summary:
            return summary
        return ""

    def _extract_affected_products(self, item: dict[str, Any]) -> list[dict[str, Any]]:
        affected = item.get("affected", [])
        if not isinstance(affected, list):
            return []
        result = []
        for affected_item in affected:
            if not isinstance(affected_item, dict):
                continue
            package = affected_item.get("package", {})
            if not isinstance(package, dict):
                continue
            ecosystem = package.get("ecosystem")
            name = package.get("name")
            if not ecosystem or not name:
                continue
            result.append(
                {"vendor": ecosystem, "product": name, "version": None, "cpe_uri": None}
            )
        return result

    def _extract_cvss_vector(self, item: dict[str, Any]) -> str | None:
        severity = item.get("severity", [])
        if not isinstance(severity, list):
            return None
        for item_severity in severity:
            if not isinstance(item_severity, dict):
                continue
            severity_type = item_severity.get("type")
            score = item.get("score")
            if not isinstance(severity_type, str):
                continue
            if not severity_type.startswith("CVSS"):
                continue
            if isinstance(score, str) and score.startswith("CVSS:"):
                return score
        return None


def normalize_osv(item: dict[str, Any]) -> dict[str, Any] | None:
    return OsvNormalizer().normalize(item)
