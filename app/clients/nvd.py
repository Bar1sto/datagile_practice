import httpx
import time
from datetime import datetime
from typing import Any


class NvdClient:
    def __init__(
        self,
        api_key: str,
        base_url: str,
        timeout_seconds: int = 90,
        max_retries: int = 2,
        retry_sleep_seconds: int = 10,
        results_per_page: int = 2000,
    ):
        self.base_url = base_url
        self.api_key = api_key
        self.timeout_seconds = timeout_seconds
        self.max_retries = max_retries
        self.retry_sleep_seconds = retry_sleep_seconds
        self.results_per_page = results_per_page

    def fetch_vulnerabilities(
        self, start_date: datetime, end_date: datetime
    ) -> list[dict]:
        start_date_str = start_date.isoformat()
        end_date_str = end_date.isoformat()
        headers = {
            "apiKey": self.api_key,
        }
        start_index = 0
        all_items = []

        while True:
            params = {
                "pubStartDate": start_date_str,
                "pubEndDate": end_date_str,
                "resultsPerPage": self.results_per_page,
                "startIndex": start_index,
            }
            data = self._request_page(params=params, headers=headers)
            page_items = data.get("vulnerabilities", [])
            if not page_items:
                break
            all_items.extend(page_items)
            total_results = data.get("totalResults", 0)
            if len(all_items) >= total_results:
                break
            start_index += self.results_per_page

        return all_items

    def _request_page(self, params: dict, headers: dict) -> dict[str, Any]:
        attempt = 1
        retryable_status = [429, 502, 503, 504]
        while attempt <= self.max_retries + 1:
            try:
                response = httpx.get(
                    self.base_url,
                    params=params,
                    headers=headers,
                    timeout=self.timeout_seconds,
                )
                response.raise_for_status()
                return response.json()
            except (httpx.Timeout, httpx.NetworkError):
                if attempt >= self.max_retries + 1:
                    raise
                else:
                    time.sleep(self.retry_sleep_seconds)
                    attempt += 1
            except httpx.HTTPStatusError as error:
                status_code = error.response.status_code
                if status_code not in retryable_status:
                    raise
                if attempt >= self.max_retries + 1:
                    raise
                else:
                    time.sleep(self.retry_sleep_seconds)
                    attempt += 1
