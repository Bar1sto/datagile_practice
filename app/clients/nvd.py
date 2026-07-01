import httpx
from datetime import datetime


class NvdClient:
    def __init__(
        self,
        api_key: str,
        base_url: str,
    ):
        self.base_url = base_url
        self.api_key = api_key

    def fetch_vulnerabilities(
        self, start_date: datetime, end_date: datetime
    ) -> list[dict]:
        start_date_str = start_date.isoformat()
        end_date_str = end_date.isoformat()
        headers = {
            "apiKey": self.api_key,
        }

        results_per_page = 2000
        start_index = 0
        all_items = []

        while True:
            params = {
                "pubStartDate": start_date_str,
                "pubEndDate": end_date_str,
                "resultsPerPage": results_per_page,
                "startIndex": start_index,
            }
            response = httpx.get(
                self.base_url,
                params=params,
                headers=headers,
                timeout=30,
            )
            response.raise_for_status()
            data = response.json()
            page_items = data.get("vulnerabilities", [])
            if not page_items:
                break
            all_items.extend(page_items)
            total_results = data.get("totalResults", 0)
            if len(all_items) >= total_results:
                break
            start_index += results_per_page

        return all_items
