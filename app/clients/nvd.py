import asyncio
from datetime import datetime
from typing import Any
import httpx


class AsyncNvdClient:
    def __init__(
        self,
        api_key: str,
        base_url: str,
        timeout_seconds: int = 90,
        max_retries: int = 2,
        retry_sleep_seconds: int = 10,
        results_per_page: int = 2000,
    ) -> None:
        self.api_key = api_key
        self.base_url = base_url
        self.timeout_seconds = timeout_seconds
        self.max_retries = max_retries
        self.retry_sleep_seconds = retry_sleep_seconds
        self.results_per_page = results_per_page

    async def fetch_vulnerabilities(
        self,
        start_date: datetime,
        end_date: datetime,
    ) -> list[dict[str, Any]]:
        start_date_str = start_date.isoformat()
        end_date_str = end_date.isoformat()
        headers = {
            "apiKey": self.api_key,
        }
        start_index = 0
        all_items: list[dict[str, Any]] = []
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(timeout=self.timeout_seconds),
        ) as client:
            while True:
                params = {
                    "pubStartDate": start_date_str,
                    "pubEndDate": end_date_str,
                    "resultsPerPage": self.results_per_page,
                    "startIndex": start_index,
                }
                data = await self._request_page(
                    client=client,
                    params=params,
                    headers=headers,
                )

                page_items = data.get("vulnerabilities", [])
                if not page_items:
                    break
                all_items.extend(page_items)
                total_results = data.get("totalResults", 0)
                if len(all_items) >= total_results:
                    break
                start_index += self.results_per_page
        return all_items

    async def _request_page(
        self,
        client: httpx.AsyncClient,
        params: dict[str, Any],
        headers: dict[str, str],
    ) -> dict[str, Any]:
        attempt = 1
        retryable_status = {
            429,
            502,
            503,
            504,
        }
        while attempt <= self.max_retries + 1:
            try:
                response = await client.get(
                    self.base_url,
                    params=params,
                    headers=headers,
                )
                response.raise_for_status()
                return response.json()
            except (httpx.TimeoutException, httpx.NetworkError):
                if attempt >= self.max_retries + 1:
                    raise
                await asyncio.sleep(self.retry_sleep_seconds)
                attempt += 1
            except httpx.HTTPStatusError as error:
                status_code = error.response.status_code
                if status_code not in retryable_status:
                    raise
                if attempt >= self.max_retries + 1:
                    raise
                await asyncio.sleep(self.retry_sleep_seconds)
                attempt += 1
        raise RuntimeError("NVD request failed after retries")
